//! Secrets are kept in the macOS Keychain, never in files Harbormaster owns.

use std::process::Command;

use anyhow::{bail, Context, Result};

/// Keychain service name under which the Protect account password is stored.
pub const PROTECT_SERVICE: &str = "harbormaster-protect";

/// The command a person runs to store a password. It prompts for the
/// password, so it never appears in shell history.
pub fn store_command(service: &str, account: &str) -> String {
    format!("security add-generic-password -U -s {service} -a {account} -w")
}

/// Reads a password from the user's Keychain.
pub fn password(service: &str, account: &str) -> Result<String> {
    // An absolute path, so a planted `security` on PATH is never run.
    let output = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .output()
        .context("running /usr/bin/security")?;
    if !output.status.success() {
        bail!("{}", explain_failure(output.status.code(), &String::from_utf8_lossy(&output.stderr), service, account));
    }
    let password = String::from_utf8(output.stdout).context("Keychain password is not valid UTF-8")?;
    Ok(password.trim_end_matches('\n').to_owned())
}

/// Turns a failed lookup into advice. A locked keychain and a missing item
/// need different fixes, so they must not be reported the same way.
fn explain_failure(code: Option<i32>, stderr: &str, service: &str, account: &str) -> String {
    let detail = stderr.trim();
    // `security` exits 44 when the item does not exist and 36 when the
    // keychain is locked and it may not prompt (typical over SSH).
    let locked = code == Some(36) || detail.contains("User interaction is not allowed");
    if locked {
        format!(
            "the Keychain is locked, so the password for \"{account}\" cannot be read. \
             In an SSH session, unlock it first:\n\n    security unlock-keychain\n\n({detail})"
        )
    } else if code == Some(44) {
        format!(
            "no Keychain item with service \"{service}\" and account \"{account}\". The account \
             must match the username in config.toml exactly. Store it with:\n\n    {}\n\n({detail})",
            store_command(service, account)
        )
    } else {
        format!("reading the Keychain failed (exit {code:?}): {detail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_and_missing_are_explained_differently() {
        let locked = explain_failure(Some(36), "security: SecKeychainSearchCopyNext: User interaction is not allowed.", "svc", "hm");
        assert!(locked.contains("locked") && locked.contains("unlock-keychain"), "{locked}");
        let missing = explain_failure(Some(44), "The specified item could not be found in the keychain.", "svc", "hm");
        assert!(missing.contains("no Keychain item") && missing.contains("-s svc -a hm"), "{missing}");
        assert!(explain_failure(Some(1), "boom", "svc", "hm").contains("boom"));
    }
}
