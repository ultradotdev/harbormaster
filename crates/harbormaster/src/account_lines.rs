//! The lines that tell the person at the terminal which UniFi Protect
//! account Harbormaster is using, and the command that stores a password
//! for it. Naming the account is the point of them: it is how someone
//! sees that the right console and the right account are configured.
//!
//! They live in one file because a code scanner treats an account name
//! as something that must never be printed. This file alone is left out
//! of scanning (see `.github/codeql/codeql-config.yml`), so that rule
//! stays on everywhere else, where it guards what matters: passwords.
//! Nothing here is ever handed a password, a key or a session token, and
//! nothing but such lines belongs here.

use std::path::Path;

pub fn signed_in(host: &str, username: &str) {
    println!("Signed in to {host} as {username}.");
}

pub fn already_configured(config: &Path, host: &str, username: &str) {
    println!("{} already names the console at {host} and the account \"{username}\".", config.display());
}

pub fn signing_in(host: &str, username: &str) {
    println!("Signing in to UniFi Protect at {host} as \"{username}\"...");
}

/// `command` is the one that stores a password for the account; it
/// names the account and asks for the password itself.
pub fn could_not_store(why: &dyn std::fmt::Display, command: &str) {
    println!("It could not be stored ({why}). To store it yourself later:\n\n    {command}\n");
}

pub fn store_it_once(command: &str) {
    eprintln!("To have it read from the Keychain next time, store it once with:\n\n    {command}\n");
}
