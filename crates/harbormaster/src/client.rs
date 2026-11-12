//! One-shot requests to a running daemon over its control socket, for the
//! commands that ask it something and exit.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use crate::control::{self, Command, Message, State, UnlockReply};
use crate::password::Secret;

/// How long the daemon gets to try a sign-in before `unlock` gives up
/// waiting for the answer. The daemon's own request timeout is shorter.
const UNLOCK_PATIENCE: Duration = Duration::from_secs(90);

fn connect(state_dir: &Path, patience: Duration) -> Result<UnixStream> {
    let path = state_dir.join(control::SOCKET_NAME);
    let stream = UnixStream::connect(&path).with_context(|| {
        format!("no Harbormaster daemon is running with the state directory {} (nothing answers on {})", state_dir.display(), path.display())
    })?;
    stream.set_read_timeout(Some(patience))?;
    Ok(stream)
}

/// Reads messages until `pick` takes one. Lines this build does not
/// understand are skipped, as the dashboard does.
fn wait_for<T>(stream: UnixStream, mut pick: impl FnMut(Message) -> Option<T>) -> Result<T> {
    for line in BufReader::new(stream).lines() {
        let line = line.context("the daemon did not answer in time")?;
        if let Some(found) = serde_json::from_str::<Message>(&line).ok().and_then(&mut pick) {
            return Ok(found);
        }
    }
    bail!("the daemon closed the connection without answering")
}

/// The daemon's current status snapshot.
pub fn state(state_dir: &Path) -> Result<State> {
    let stream = connect(state_dir, Duration::from_secs(5))?;
    wait_for(stream, |message| match message {
        Message::State(state) => Some(*state),
        _ => None,
    })
}

/// Hands the daemon the Protect password and waits to hear how the
/// sign-in went.
pub fn unlock(state_dir: &Path, password: Secret) -> Result<UnlockReply> {
    let mut stream = connect(state_dir, UNLOCK_PATIENCE)?;
    let mut line = serde_json::to_string(&Command::Unlock { password })?;
    line.push('\n');
    let sent = stream.write_all(line.as_bytes());
    line.zeroize();
    sent.context("sending the password to the daemon")?;
    wait_for(stream, |message| match message {
        Message::Unlock(reply) => Some(reply),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn unlock_sends_one_line_and_returns_the_daemons_answer() {
        let dir = std::env::temp_dir().join(format!("hm-client-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(state(&dir).unwrap_err().to_string().contains("no Harbormaster daemon is running"));

        let listener = UnixListener::bind(dir.join(control::SOCKET_NAME)).unwrap();
        let daemon = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // What every client hears first, and something from the future.
            stream.write_all(b"{\"type\":\"state\",\"name\":\"H\"}\n{\"type\":\"metrics\"}\n").unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap()).read_line(&mut request).unwrap();
            stream.write_all(b"{\"type\":\"unlock\",\"signed_in\":true,\"devices\":18}\n").unwrap();
            request
        });
        let reply = unlock(&dir, Secret::new("correct horse".into())).unwrap();
        assert_eq!(reply, UnlockReply { signed_in: true, devices: 18, ..UnlockReply::default() });
        assert_eq!(daemon.join().unwrap(), "{\"type\":\"unlock\",\"password\":\"correct horse\"}\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
