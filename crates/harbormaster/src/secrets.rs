//! Where Harbormaster finds the UniFi Protect password.
//!
//! An unattended machine cannot use the login Keychain: it stays locked
//! until someone logs in at the console, and is locked for SSH sessions.
//! So a password file in the state directory is checked first, then the
//! Keychain if it answers without asking for anything. A daemon that finds
//! neither starts anyway and waits for `harbormaster unlock`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::keychain;
use crate::password::Secret;

pub const PROTECT_PASSWORD_FILE: &str = "protect-password";

pub fn protect_password_path(state_dir: &Path) -> PathBuf {
    state_dir.join(PROTECT_PASSWORD_FILE)
}

/// Reads a secret file, refusing one that other users could read or that
/// someone else owns.
fn read_private_file(path: &Path) -> Result<Option<String>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("checking {}", path.display())),
    };
    if !metadata.is_file() {
        bail!("{} must be a regular file, not a link or directory", path.display());
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { geteuid() };
    if metadata.uid() != me {
        bail!("{} is owned by another user; refusing to use it", path.display());
    }
    if metadata.mode() & 0o077 != 0 {
        bail!(
            "{} is readable by other users. Restrict it with:\n\n    chmod 600 \"{}\"\n",
            path.display(),
            path.display()
        );
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let secret = text.trim_end_matches(['\n', '\r']);
    if secret.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(Some(secret.to_owned()))
}

extern "C" {
    fn geteuid() -> u32;
}

pub fn protect_password(state_dir: &Path, username: &str) -> Result<String> {
    if let Some(password) = read_private_file(&protect_password_path(state_dir))? {
        return Ok(password);
    }
    keychain::password(keychain::PROTECT_SERVICE, username).with_context(|| {
        format!(
            "no password file at {} either (for unattended use, put the password there with mode 600)",
            protect_password_path(state_dir).display()
        )
    })
}

/// How long the daemon lets the Keychain take before treating it as locked.
const KEYCHAIN_PATIENCE: std::time::Duration = std::time::Duration::from_secs(5);

/// What the daemon looks for when it starts: the password file, then the
/// Keychain. Finding nothing is not an error; the daemon waits.
pub fn at_start(state_dir: &Path, username: &str) -> Option<Secret> {
    find_at_start(state_dir, username, |username| {
        if cfg!(target_os = "macos") {
            keychain::lookup(keychain::PROTECT_SERVICE, username, Some(KEYCHAIN_PATIENCE))
        } else {
            Err(keychain::Failure::Missing("there is no Keychain on this system".into()))
        }
    })
}

fn find_at_start(
    state_dir: &Path,
    username: &str,
    keychain: impl FnOnce(&str) -> Result<Secret, keychain::Failure>,
) -> Option<Secret> {
    let path = protect_password_path(state_dir);
    match read_private_file(&path) {
        Ok(Some(password)) => {
            tracing::info!("using the Protect password in {}", path.display());
            return Some(Secret::new(password));
        }
        Ok(None) => {}
        // A file that cannot be trusted is not used, and not fatal either.
        Err(e) => tracing::warn!("ignoring the password file: {e:#}"),
    }
    match keychain(username) {
        Ok(password) => {
            tracing::info!("using the Protect password for \"{username}\" from the Keychain");
            Some(password)
        }
        Err(keychain::Failure::Locked(_)) => {
            tracing::info!("the Keychain is locked, so the Protect password cannot be read from it yet");
            None
        }
        Err(keychain::Failure::Missing(_)) => {
            tracing::info!("no Protect password for \"{username}\" in a password file or the Keychain");
            None
        }
        Err(keychain::Failure::Other(why)) => {
            tracing::warn!("{why}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_file_comes_first_then_the_keychain_then_waiting() {
        let (in_file, in_keychain) = (crate::test_random::word(), crate::test_random::word());
        let file = temp_file("order", &format!("{in_file}\n"), 0o600);
        let dir = file.parent().unwrap();
        std::fs::rename(&file, protect_password_path(dir)).unwrap();
        let unused = |_: &str| -> Result<Secret, keychain::Failure> { panic!("the Keychain must not be asked") };
        assert_eq!(find_at_start(dir, "hm", unused).unwrap().expose(), in_file);

        // No file: the Keychain is asked, for the configured username.
        std::fs::remove_file(protect_password_path(dir)).unwrap();
        let found = find_at_start(dir, "hm", |user| {
            assert_eq!(user, "hm");
            Ok(Secret::new(in_keychain.clone()))
        });
        assert_eq!(found.unwrap().expose(), in_keychain);

        // Neither: the daemon waits, whatever the Keychain's reason.
        for failure in [
            keychain::Failure::Locked("locked".into()),
            keychain::Failure::Missing("missing".into()),
            keychain::Failure::Other("broken".into()),
        ] {
            assert!(find_at_start(dir, "hm", |_| Err(failure)).is_none());
        }

        // A file other users can read is passed over, not trusted.
        std::fs::write(protect_password_path(dir), format!("{}\n", crate::test_random::word())).unwrap();
        std::fs::set_permissions(protect_password_path(dir), std::fs::Permissions::from_mode(0o644)).unwrap();
        let found = find_at_start(dir, "hm", |_| Ok(Secret::new(in_keychain.clone())));
        assert_eq!(found.unwrap().expose(), in_keychain);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn temp_file(name: &str, contents: &str, mode: u32) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hm-secret-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn reads_private_file_and_trims_newline() {
        let path = temp_file("ok", "hunter2 with spaces \n", 0o600);
        assert_eq!(read_private_file(&path).unwrap().as_deref(), Some("hunter2 with spaces "));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn refuses_files_others_can_read_and_empty_files() {
        let path = temp_file("open", "hunter2\n", 0o644);
        assert!(read_private_file(&path).unwrap_err().to_string().contains("chmod 600"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();

        let path = temp_file("empty", "\n", 0o600);
        assert!(read_private_file(&path).unwrap_err().to_string().contains("empty"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn missing_file_is_not_an_error_and_links_are_refused() {
        let path = temp_file("link", "hunter2\n", 0o600);
        let dir = path.parent().unwrap();
        assert!(read_private_file(&dir.join("absent")).unwrap().is_none());
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_private_file(&link).unwrap_err().to_string().contains("regular file"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
