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

impl<S: Subscriber> Layer<S> for LogBuffer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = *event.metadata().level();
        // Debug chatter stays on stderr only.
        if level > Level::INFO {
            return;
        }
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        self.push(LogLine {
            time: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
            level: level.to_string(),
            message: visitor.0,
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
}
