//! The daemon's log on disk, for when nobody is attached to see it.
//!
//! A detached daemon has no terminal, and the dashboard only remembers the
//! last few hundred lines, so every line also goes to `harbormaster.log`
//! in the state directory. The file is the owner's alone, is stamped in
//! local time, and cannot grow without bound: at the size cap it is renamed
//! to `harbormaster.log.1`, replacing the one before, and a new file begun.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context as LayerContext, Layer};

use crate::clock;

pub const FILE_NAME: &str = "harbormaster.log";
/// The one older file that is kept.
pub const ROTATED_NAME: &str = "harbormaster.log.1";

/// Size at which the log is rotated. With one older file kept, the log
/// never takes more than about twice this.
const CAP: u64 = 5 * 1024 * 1024;

struct Inner {
    path: PathBuf,
    rotated: PathBuf,
    file: File,
    size: u64,
    cap: u64,
}

#[derive(Clone)]
pub struct LogFile {
    inner: Arc<Mutex<Inner>>,
    /// Seconds local time is ahead of UTC at a given moment.
    zone: fn(u64) -> i64,
}

fn open_private(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new().append(true).create(true).mode(0o600).open(path)?;
    // The mode above only applies to a file that did not exist yet.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

impl LogFile {
    /// Opens the log in the state directory, carrying on from where the
    /// last run left off.
    pub fn open(state_dir: &Path) -> Result<Self> {
        Self::with(state_dir, CAP, clock::local_offset)
    }

    fn with(state_dir: &Path, cap: u64, zone: fn(u64) -> i64) -> Result<Self> {
        let path = state_dir.join(FILE_NAME);
        let file = open_private(&path).with_context(|| format!("opening {}", path.display()))?;
        let size = file.metadata().map_or(0, |m| m.len());
        let inner = Inner { rotated: state_dir.join(ROTATED_NAME), path, file, size, cap };
        Ok(Self { inner: Arc::new(Mutex::new(inner)), zone })
    }

    /// Appends one line. A log that cannot be written must not take the
    /// bridge down, so failures are dropped.
    fn write(&self, line: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let length = line.len() as u64 + 1;
        if inner.size > 0 && inner.size + length > inner.cap {
            // Rename, then start afresh. If either step fails the old
            // file simply keeps growing until a later line succeeds.
            if std::fs::rename(&inner.path, &inner.rotated).is_ok() {
                if let Ok(file) = open_private(&inner.path) {
                    inner.file = file;
                    inner.size = 0;
                }
            }
        }
        if inner.file.write_all(format!("{line}\n").as_bytes()).is_ok() {
            inner.size += length;
        }
    }
}

impl<S: Subscriber> Layer<S> for LogFile {
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let stamp = clock::date_time(now, (self.zone)(now));
        self.write(&format!("{stamp} {:<5} {}", event.metadata().level(), crate::logbuf::message(event)));
    }
}

/// The last `count` lines of the log, reaching back into the older file
/// if the current one is short.
fn tail(state_dir: &Path, count: usize) -> Vec<String> {
    let read = |name: &str| std::fs::read(state_dir.join(name)).map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    let current = read(FILE_NAME).unwrap_or_default();
    let mut lines: Vec<String> = current.lines().map(str::to_owned).collect();
    if lines.len() < count {
        let older = read(ROTATED_NAME).unwrap_or_default();
        let mut all: Vec<String> = older.lines().map(str::to_owned).collect();
        all.append(&mut lines);
        lines = all;
    }
    lines.split_off(lines.len().saturating_sub(count))
}

/// `harbormaster logs`: prints the end of the log and, with `follow`,
/// every line written from then on until interrupted.
pub fn show(state_dir: &Path, count: usize, follow: bool) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let path = state_dir.join(FILE_NAME);
    if !path.exists() {
        anyhow::bail!("there is no log yet at {}", path.display());
    }
    let mut out = std::io::stdout().lock();
    // Whoever reads the output may stop early (`| head`); that is no error.
    let mut print = |text: &str| out.write_all(text.as_bytes()).and_then(|()| out.flush()).is_ok();
    // Where the file ends now, so that following starts after what is shown.
    let mut position = std::fs::metadata(&path).map_or(0, |m| m.len());
    for line in tail(state_dir, count) {
        if !print(&format!("{line}\n")) {
            return Ok(());
        }
    }
    while follow {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let Ok(length) = std::fs::metadata(&path).map(|m| m.len()) else { continue };
        // A shorter file is a new one: the old was rotated away.
        if length < position {
            position = 0;
        }
        if length == position {
            continue;
        }
        let mut fresh = Vec::new();
        let read = File::open(&path).and_then(|mut file| {
            file.seek(SeekFrom::Start(position))?;
            file.take(length - position).read_to_end(&mut fresh)
        });
        if read.is_ok() {
            position += fresh.len() as u64;
            if !print(&String::from_utf8_lossy(&fresh)) {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hm-logfile-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn lines_are_stamped_in_local_time_and_private() {
        let dir = temp_dir("lines");
        // Left behind by something careless: it is tightened, not trusted.
        std::fs::write(dir.join(FILE_NAME), "earlier\n").unwrap();
        std::fs::set_permissions(dir.join(FILE_NAME), std::fs::Permissions::from_mode(0o644)).unwrap();

        let log = LogFile::with(&dir, CAP, |_| -8 * 3600).unwrap();
        let subscriber = tracing_subscriber::registry().with(log);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("listening");
            tracing::warn!(port = 80, "busy");
        });
        let text = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "earlier", "a restart appends");
        assert!(lines[1].ends_with(" INFO  listening") && lines[2].ends_with(" WARN  busy port=80"), "{text}");
        // 2026-11-12 14:03:22, give or take the digits.
        let stamp = lines[1].as_bytes();
        assert!(stamp[..19].iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b' ',
            13 | 16 => *b == b':',
            _ => b.is_ascii_digit(),
        }), "{text}");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let hour = |at: u64| clock::date_time(at, -8 * 3600)[..13].to_owned();
        assert!(lines[1].starts_with(&hour(now)) || lines[1].starts_with(&hour(now - 5)), "not Pacific time: {text}");
        assert_eq!(mode(&dir.join(FILE_NAME)), 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_end_of_the_log_reaches_into_the_older_file() {
        let dir = temp_dir("tail");
        assert!(tail(&dir, 5).is_empty() && show(&dir, 5, false).is_err(), "no log yet");
        std::fs::write(dir.join(ROTATED_NAME), "one\ntwo\nthree\n").unwrap();
        std::fs::write(dir.join(FILE_NAME), "four\nfive\n").unwrap();
        assert_eq!(tail(&dir, 1), ["five"]);
        assert_eq!(tail(&dir, 2), ["four", "five"]);
        assert_eq!(tail(&dir, 4), ["two", "three", "four", "five"]);
        assert_eq!(tail(&dir, 50).len(), 5);
        assert!(show(&dir, 2, false).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_log_is_capped_and_keeps_one_older_file() {
        let dir = temp_dir("cap");
        let log = LogFile::with(&dir, 200, |_| 0).unwrap();
        let line = |i: usize| format!("line {i:03} {}", "x".repeat(50));
        for i in 0..40 {
            log.write(&line(i));
        }
        let current = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        let older = std::fs::read_to_string(dir.join(ROTATED_NAME)).unwrap();
        assert!(current.len() <= 200 && older.len() <= 200, "{} and {}", current.len(), older.len());
        assert!(current.ends_with(&format!("{}\n", line(39))), "the newest line is in the current file");
        // Three lines fit under the cap; the older file holds the three before.
        assert_eq!(older.lines().count(), 3);
        let last_older: usize = older.lines().last().unwrap()[5..8].parse().unwrap();
        let first_current: usize = current.lines().next().unwrap()[5..8].parse().unwrap();
        assert_eq!(last_older + 1, first_current, "nothing is lost at the join");
        assert_eq!((mode(&dir.join(FILE_NAME)), mode(&dir.join(ROTATED_NAME))), (0o600, 0o600));
        // Only ever the two files.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);

        // A line longer than the cap is still written, alone.
        log.write(&"y".repeat(500));
        assert_eq!(std::fs::read_to_string(dir.join(FILE_NAME)).unwrap().lines().count(), 1);

        // A restart carries on counting from the file's real size.
        let again = LogFile::with(&dir, 200, |_| 0).unwrap();
        again.write("after restart");
        assert_eq!(std::fs::read_to_string(dir.join(FILE_NAME)).unwrap(), "after restart\n");
        assert!(std::fs::read_to_string(dir.join(ROTATED_NAME)).unwrap().starts_with("yyy"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
