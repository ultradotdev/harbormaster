//! The macOS Keychain, where the Protect password is looked for and where
//! setup can store it. Harbormaster never writes a password to a file. The
//! optional `protect-password` file, for machines that must start with
//! nobody there, is the owner's to create; see `secrets.rs`.

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

/// Stores a password in the user's Keychain, replacing one already there.
/// It is handed to `security` on its input, never on a command line, where
/// other programs could read it.
pub fn store(service: &str, account: &str, password: &Secret) -> Result<(), Failure> {
    use std::io::Write;
    let quoted = |text: &str| format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""));
    if [service, account, password.expose()].iter().any(|text| text.contains(['\n', '\r'])) {
        return Err(Failure::Other("a password with a line break in it cannot be stored".into()));
    }
    let mut child = Command::new("/usr/bin/security")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Failure::Other(format!("running /usr/bin/security: {e}")))?;
    let mut line = format!(
        "add-generic-password -U -s {} -a {} -w {}\n",
        quoted(service),
        quoted(account),
        quoted(password.expose())
    );
    let sent = child.stdin.take().map(|mut input| input.write_all(line.as_bytes()));
    zeroize::Zeroize::zeroize(&mut line);
    let output = child.wait_with_output().map_err(|e| Failure::Other(format!("running /usr/bin/security: {e}")))?;
    if !matches!(sent, Some(Ok(()))) {
        return Err(Failure::Other("could not hand the password to /usr/bin/security".into()));
    }
    // `security -i` reports success whatever its commands did, so the
    // proof is reading the password back.
    match lookup(service, account, Some(Duration::from_secs(5))) {
        Ok(stored) if stored.expose() == password.expose() => Ok(()),
        Ok(_) => Err(Failure::Other("the Keychain holds a different password than the one given".into())),
        Err(Failure::Missing(_)) => {
            let said = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if said.contains("User interaction is not allowed") {
                Err(Failure::Locked("the Keychain is locked".into()))
            } else {
                Err(Failure::Other(format!("the Keychain did not take the password{}", if said.is_empty() { String::new() } else { format!(": {said}") })))
            }
        }
        Err(failure) => Err(failure),
    }
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
