//! `harbormaster unlock`: gets the UniFi Protect password and hands it to
//! the running daemon, which keeps it in memory only.
//!
//! The daemon runs detached and cannot ask anyone for anything, so this is
//! run by the owner in their own terminal, locally or over `ssh -t`.
//! Where the password comes from depends on the system and sits behind
//! `Platform`; the daemon neither knows nor cares.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::keychain::{self, Failure};
use crate::password::Secret;
use crate::{client, config, tty};

/// What a system offers for finding the password. macOS has the Keychain.
/// A Linux implementation would answer `stored` from a password file or a
/// systemd credential, and leave the rest as it is here.
pub trait Platform {
    /// The password as the system has it stored, without asking for it.
    fn stored(&mut self, username: &str) -> Result<Secret, Failure>;
    /// Unlocks the system's store. The system does the asking, on this
    /// terminal; Harbormaster never sees what is typed.
    fn unlock_store(&mut self) -> Result<()>;
    /// Locks the store again after `unlock_store`.
    fn relock_store(&mut self);
    /// Asks the person for the Protect password itself, unseen.
    fn ask(&mut self, prompt: &str) -> Result<Secret>;
    /// How to store the password so that it need not be typed next time.
    fn store_hint(&self, username: &str) -> Option<String>;
}

struct Mac;

impl Platform for Mac {
    fn stored(&mut self, username: &str) -> Result<Secret, Failure> {
        keychain::lookup(keychain::PROTECT_SERVICE, username, None)
    }

    fn unlock_store(&mut self) -> Result<()> {
        keychain::unlock_interactively()
    }

    fn relock_store(&mut self) {
        keychain::lock();
    }

    fn ask(&mut self, prompt: &str) -> Result<Secret> {
        tty::read_password(prompt)
    }

    fn store_hint(&self, username: &str) -> Option<String> {
        Some(keychain::store_command(keychain::PROTECT_SERVICE, username))
    }
}

/// A system with no password store Harbormaster knows: it just asks.
struct Plain;

impl Platform for Plain {
    fn stored(&mut self, _username: &str) -> Result<Secret, Failure> {
        Err(Failure::Missing("no password store is supported on this system yet".into()))
    }

    fn unlock_store(&mut self) -> Result<()> {
        Ok(())
    }

    fn relock_store(&mut self) {}

    fn ask(&mut self, prompt: &str) -> Result<Secret> {
        tty::read_password(prompt)
    }

    fn store_hint(&self, _username: &str) -> Option<String> {
        None
    }
}

fn platform() -> Box<dyn Platform> {
    if cfg!(target_os = "macos") {
        Box::new(Mac)
    } else {
        Box::new(Plain)
    }
}

/// Finds the password: from the store if it is there, unlocking the store
/// once if it is locked, and by asking for it if it is not stored.
fn obtain(platform: &mut dyn Platform, username: &str) -> Result<Secret> {
    let found = match platform.stored(username) {
        Err(Failure::Locked(_)) => {
            eprintln!("The Keychain is locked. macOS will now ask for your Mac login password to unlock it.");
            platform.unlock_store()?;
            let found = platform.stored(username);
            // Leave the Keychain as it was found.
            platform.relock_store();
            if let Err(Failure::Locked(why)) = found {
                bail!("{why}");
            }
            found
        }
        other => other,
    };
    match found {
        Ok(password) => Ok(password),
        Err(failure) => {
            if let Failure::Other(why) = failure {
                eprintln!("{why}");
            }
            let password = platform.ask(&format!("UniFi Protect password for \"{username}\": "))?;
            if password.is_empty() {
                bail!("no password was entered");
            }
            if let Some(command) = platform.store_hint(username) {
                crate::account_lines::store_it_once(&command);
            }
            Ok(password)
        }
    }
}

/// How long to wait for the daemon's own retries after a failed sign-in.
const RETRY_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// Watches the daemon until it is signed in or `wait` has passed. Returns
/// how many devices are published once it is.
fn wait_for_retry(wait: std::time::Duration, mut state: impl FnMut() -> Option<crate::control::State>) -> Option<usize> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        if let Some(state) = state() {
            if state.console.as_ref().is_some_and(|console| console.connected) {
                return Some(state.devices.len());
            }
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

pub fn run(state_dir: &Path, from_stdin: bool) -> Result<()> {
    let protect = config::load(state_dir)?
        .protect
        .with_context(|| format!("{} has no [protect] section, so there is nothing to unlock", config::path(state_dir).display()))?;
    // Ask the daemon first: nobody should type a password it does not need.
    let state = client::state(state_dir)?;
    if let Some(console) = state.console.as_ref().filter(|console| console.connected) {
        println!("Already signed in to UniFi Protect at {} ({} devices). Nothing to do.", console.host, state.devices.len());
        return Ok(());
    }
    let password = if from_stdin { tty::read_stdin()? } else { obtain(platform().as_mut(), &protect.username)? };
    crate::account_lines::signing_in(&protect.host, &protect.username);
    let reply = client::unlock(state_dir, password)?;
    if reply.signed_in {
        println!("Signed in. {} devices are published to HomeKit.", reply.devices);
        return Ok(());
    }
    if reply.kept {
        // The daemon tries again within seconds, and a first attempt that
        // fails is often followed by one that works: macOS turns away a
        // new build's first connection while it checks its permission.
        println!("The first attempt did not get through ({}). Waiting for the daemon to try again...", reply.detail);
        let retried = wait_for_retry(RETRY_WAIT, || client::state(state_dir).ok());
        if let Some(devices) = retried {
            println!("Signed in. {devices} devices are published to HomeKit.");
            return Ok(());
        }
        bail!(
            "not signed in: {}\nThe daemon kept the password and keeps trying; there is no need to unlock again.",
            reply.detail
        );
    }
    bail!("not signed in: {}\nThe daemon discarded the password and is waiting for another.", reply.detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_first_attempt_is_given_time_to_come_good() {
        use crate::control::{Console, Device, State};
        let state = |connected| State {
            console: Some(Console { connected, ..Console::default() }),
            devices: vec![Device::default(); 3],
            ..State::default()
        };
        let mut asked = 0;
        let signed_in = wait_for_retry(std::time::Duration::from_secs(5), || {
            asked += 1;
            // No answer, then still failing, then through.
            [None, Some(state(false)), Some(state(true))][asked - 1].clone()
        });
        assert_eq!((signed_in, asked), (Some(3), 3));
        assert_eq!(wait_for_retry(std::time::Duration::ZERO, || Some(state(false))), None, "it gives up in the end");
    }

    /// A system whose store answers from a script, recording what was done.
    struct Scripted {
        store: Vec<Result<&'static str, Failure>>,
        typed: &'static str,
        did: Vec<&'static str>,
    }

    impl Scripted {
        fn new(store: Vec<Result<&'static str, Failure>>, typed: &'static str) -> Self {
            Self { store, typed, did: Vec::new() }
        }
    }

    impl Platform for Scripted {
        fn stored(&mut self, username: &str) -> Result<Secret, Failure> {
            assert_eq!(username, "hm");
            self.did.push("read");
            self.store.remove(0).map(|password| Secret::new(password.to_owned()))
        }

        fn unlock_store(&mut self) -> Result<()> {
            self.did.push("unlock");
            Ok(())
        }

        fn relock_store(&mut self) {
            self.did.push("relock");
        }

        fn ask(&mut self, prompt: &str) -> Result<Secret> {
            assert!(prompt.contains("\"hm\""));
            self.did.push("ask");
            Ok(Secret::new(self.typed.to_owned()))
        }

        fn store_hint(&self, _username: &str) -> Option<String> {
            None
        }
    }

    fn locked() -> Failure {
        Failure::Locked("locked".into())
    }

    fn missing() -> Failure {
        Failure::Missing("missing".into())
    }

    #[test]
    fn an_unlocked_store_is_read_without_asking_anything() {
        let mut system = Scripted::new(vec![Ok("stored")], "");
        assert_eq!(obtain(&mut system, "hm").unwrap().expose(), "stored");
        assert_eq!(system.did, ["read"]);
    }

    #[test]
    fn a_locked_store_is_unlocked_exactly_once_then_read_and_locked_again() {
        let mut system = Scripted::new(vec![Err(locked()), Ok("stored")], "");
        assert_eq!(obtain(&mut system, "hm").unwrap().expose(), "stored");
        assert_eq!(system.did, ["read", "unlock", "read", "relock"]);

        // Still locked afterwards: give up rather than ask a second time.
        let mut system = Scripted::new(vec![Err(locked()), Err(locked())], "");
        assert!(obtain(&mut system, "hm").is_err());
        assert_eq!(system.did, ["read", "unlock", "read", "relock"]);
    }

    #[test]
    fn with_nothing_stored_the_password_itself_is_asked_for() {
        let mut system = Scripted::new(vec![Err(missing())], "typed");
        assert_eq!(obtain(&mut system, "hm").unwrap().expose(), "typed");
        assert_eq!(system.did, ["read", "ask"]);

        // Unlocked, and then found to hold no such item.
        let mut system = Scripted::new(vec![Err(locked()), Err(missing())], "typed");
        assert_eq!(obtain(&mut system, "hm").unwrap().expose(), "typed");
        assert_eq!(system.did, ["read", "unlock", "read", "relock", "ask"]);

        let mut system = Scripted::new(vec![Err(missing())], "");
        assert!(obtain(&mut system, "hm").unwrap_err().to_string().contains("no password"));
    }
}
