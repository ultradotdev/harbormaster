//! Keeps recent log lines in memory and fans new ones out to attached TUIs,
//! alongside the normal stderr output.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::control::LogLine;

/// Lines kept for a TUI that attaches later.
const BACKLOG: usize = 500;

#[derive(Clone)]
pub struct LogBuffer {
    recent: Arc<Mutex<VecDeque<LogLine>>>,
    live: broadcast::Sender<LogLine>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self { recent: Arc::new(Mutex::new(VecDeque::new())), live: broadcast::channel(256).0 }
    }

    /// The backlog plus a receiver for everything logged after it. Taken
    /// under one lock so no line is missed or duplicated between the two.
    pub fn attach(&self) -> (Vec<LogLine>, broadcast::Receiver<LogLine>) {
        let recent = self.recent.lock().unwrap();
        (recent.iter().cloned().collect(), self.live.subscribe())
    }

    fn push(&self, line: LogLine) {
        let mut recent = self.recent.lock().unwrap();
        if recent.len() == BACKLOG {
            recent.pop_front();
        }
        recent.push_back(line.clone());
        // An error only means no TUI is attached.
        let _ = self.live.send(line);
    }
}

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}

/// An event's message followed by its fields, as one line of text.
pub fn message(event: &Event<'_>) -> String {
    let mut visitor = MessageVisitor(String::new());
    event.record(&mut visitor);
    printable(&visitor.0)
}

/// `text` with every control character spelled out, as `\u{1b}` and the
/// like. Log lines carry text from outside: device names from the console,
/// what ffmpeg says, a controller's name for itself. Printed raw, an
/// escape sequence among it could move the cursor, recolour the screen or
/// retitle the window of whoever reads the log, and a line break could
/// make one line pass for two.
pub fn printable(text: &str) -> String {
    if !text.contains(char::is_control) {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

impl<S: Subscriber> Layer<S> for LogBuffer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = *event.metadata().level();
        // Debug chatter stays on stderr only.
        if level > Level::INFO {
            return;
        }
        self.push(LogLine {
            time: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
            level: level.to_string(),
            message: message(event),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn captures_info_and_above_with_backlog_limit() {
        let buffer = LogBuffer::new();
        let subscriber = tracing_subscriber::registry().with(buffer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("hidden");
            for i in 0..BACKLOG + 5 {
                tracing::info!("line {i}");
            }
            tracing::warn!(port = 80, "busy");
        });
        let (recent, _live) = buffer.attach();
        assert_eq!(recent.len(), BACKLOG);
        assert!(recent.iter().all(|l| l.message != "hidden"));
        let last = recent.last().unwrap();
        assert_eq!((last.level.as_str(), last.message.as_str()), ("WARN", "busy port=80"));
    }

    #[test]
    fn control_characters_in_a_message_are_spelled_out() {
        assert_eq!(printable("Front Door: streaming"), "Front Door: streaming");
        assert_eq!(printable("caf\u{e9} \u{1f6aa}"), "caf\u{e9} \u{1f6aa}", "other alphabets and symbols are left alone");
        // Clear the screen, retitle the window, forge a second line.
        let hostile = "Porch\u{1b}[2J\u{1b}]0;gone\u{7}\r\n2026-01-01 INFO all is well\u{9b}";
        let safe = printable(hostile);
        assert_eq!(safe, "Porch\\u{1b}[2J\\u{1b}]0;gone\\u{7}\\r\\n2026-01-01 INFO all is well\\u{9b}");
        assert!(!safe.contains(char::is_control));

        // And that is what reaches both the dashboard and the log file.
        let buffer = LogBuffer::new();
        let subscriber = tracing_subscriber::registry().with(buffer.clone());
        let name = "Porch\u{1b}[31m";
        tracing::subscriber::with_default(subscriber, || tracing::info!("{name}: the camera is not reachable"));
        let (recent, _live) = buffer.attach();
        assert_eq!(recent.last().unwrap().message, "Porch\\u{1b}[31m: the camera is not reachable");
    }
}
