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
        bail!(
            "no password for account \"{account}\" in the Keychain. Store it with:\n\n    {}\n",
            store_command(service, account)
        );
    }
    let password = String::from_utf8(output.stdout).context("Keychain password is not valid UTF-8")?;
    Ok(password.trim_end_matches('\n').to_owned())
}
