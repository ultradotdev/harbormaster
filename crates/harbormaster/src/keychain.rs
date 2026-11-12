//! Secrets are kept in the macOS Keychain, never in files Harbormaster owns.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::password::Secret;

/// Keychain service name under which the Protect account password is stored.
pub const PROTECT_SERVICE: &str = "harbormaster-protect";

/// The command a person runs to store a password. It prompts for the
/// password, so it never appears in shell history.
pub fn store_command(service: &str, account: &str) -> String {
    format!("security add-generic-password -U -s {service} -a {account} -w")
}

/// Why a Keychain lookup gave no password. A locked Keychain and a missing
/// item need different fixes, so they are told apart.
#[derive(Debug, PartialEq)]
pub enum Failure {
    /// The Keychain is locked and may not ask for its password here.
    Locked(String),
    /// There is no such item.
    Missing(String),
    Other(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Failure::Locked(why) | Failure::Missing(why) | Failure::Other(why)) = self;
        f.write_str(why)
    }
}

/// Reads a password from the user's Keychain.
pub fn password(service: &str, account: &str) -> Result<String> {
    match lookup(service, account, None) {
        Ok(password) => Ok(password.expose().to_owned()),
        Err(failure) => bail!("{failure}"),
    }
}

/// Reads a password from the user's Keychain. With `patience` set, a
/// lookup that has not answered by then is given up as locked: at a Mac's
/// own screen a locked Keychain makes `security` put up a dialog and wait,
/// which a daemon must never do.
pub fn lookup(service: &str, account: &str, patience: Option<Duration>) -> Result<Secret, Failure> {
    // An absolute path, so a planted `security` on PATH is never run.
    let mut child = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Failure::Other(format!("running /usr/bin/security: {e}")))?;
    if let Some(patience) = patience {
        let deadline = Instant::now() + patience;
        // The answer is a few dozen bytes, so the pipes cannot fill up.
        while matches!(child.try_wait(), Ok(None)) {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Failure::Locked("the Keychain did not answer without asking for its password".into()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let output = child.wait_with_output().map_err(|e| Failure::Other(format!("running /usr/bin/security: {e}")))?;
    if !output.status.success() {
        return Err(explain_failure(output.status.code(), &String::from_utf8_lossy(&output.stderr), service, account));
    }
    let mut text =
        String::from_utf8(output.stdout).map_err(|_| Failure::Other("Keychain password is not valid UTF-8".into()))?;
    let password = Secret::new(text.trim_end_matches('\n').to_owned());
    zeroize::Zeroize::zeroize(&mut text);
    Ok(password)
}

/// Unlocks the login Keychain. `security` asks for the Mac login password
/// on the terminal this runs in; Harbormaster never sees it.
pub fn unlock_interactively() -> Result<()> {
    let status = Command::new("/usr/bin/security").arg("unlock-keychain").status().context("running /usr/bin/security")?;
    if !status.success() {
        bail!("the Keychain was not unlocked");
    }
    Ok(())
}

/// Locks the login Keychain again.
pub fn lock() {
    let _ = Command::new("/usr/bin/security").arg("lock-keychain").stdin(Stdio::null()).status();
}

/// Turns a failed lookup into advice.
fn explain_failure(code: Option<i32>, stderr: &str, service: &str, account: &str) -> Failure {
    let detail = stderr.trim();
    // `security` exits 44 when the item does not exist and 36 when the
    // keychain is locked and it may not prompt (typical over SSH).
    let locked = code == Some(36) || detail.contains("User interaction is not allowed");
    if locked {
        Failure::Locked(format!(
            "the Keychain is locked, so the password for \"{account}\" cannot be read. \
             In an SSH session, unlock it first:\n\n    security unlock-keychain\n\n({detail})"
        ))
    } else if code == Some(44) {
        Failure::Missing(format!(
            "no Keychain item with service \"{service}\" and account \"{account}\". The account \
             must match the username in config.toml exactly. Store it with:\n\n    {}\n\n({detail})",
            store_command(service, account)
        ))
    } else {
        Failure::Other(format!("reading the Keychain failed (exit {code:?}): {detail}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_and_missing_are_explained_differently() {
        let locked = explain_failure(Some(36), "security: SecKeychainSearchCopyNext: User interaction is not allowed.", "svc", "hm");
        assert!(matches!(locked, Failure::Locked(_)));
        let locked = locked.to_string();
        assert!(locked.contains("locked") && locked.contains("unlock-keychain"), "{locked}");
        let missing = explain_failure(Some(44), "The specified item could not be found in the keychain.", "svc", "hm");
        assert!(matches!(missing, Failure::Missing(_)));
        let missing = missing.to_string();
        assert!(missing.contains("no Keychain item") && missing.contains("-s svc -a hm"), "{missing}");
        assert!(explain_failure(Some(1), "boom", "svc", "hm").to_string().contains("boom"));
    }
}
