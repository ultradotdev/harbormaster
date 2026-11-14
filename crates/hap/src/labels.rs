//! The fixed strings HomeKit has every accessory and controller mix into
//! their key derivation. The protocol sets them, they are the same in
//! every HomeKit product, and they are not secrets: what keeps a session
//! private is the key material they are mixed with.
//!
//! They live in one file because a code scanner cannot tell a published
//! protocol constant from a secret someone left in the source. This file
//! alone is left out of scanning (see `.github/codeql/codeql-config.yml`),
//! so the rule stays on everywhere else. Nothing but such constants
//! belongs here.

pub(crate) const PAIR_SETUP_ENCRYPT_SALT: &[u8] = b"Pair-Setup-Encrypt-Salt";
pub(crate) const PAIR_SETUP_ENCRYPT_INFO: &[u8] = b"Pair-Setup-Encrypt-Info";
pub(crate) const PAIR_SETUP_CONTROLLER_SIGN_SALT: &[u8] = b"Pair-Setup-Controller-Sign-Salt";
pub(crate) const PAIR_SETUP_CONTROLLER_SIGN_INFO: &[u8] = b"Pair-Setup-Controller-Sign-Info";
pub(crate) const PAIR_SETUP_ACCESSORY_SIGN_SALT: &[u8] = b"Pair-Setup-Accessory-Sign-Salt";
pub(crate) const PAIR_SETUP_ACCESSORY_SIGN_INFO: &[u8] = b"Pair-Setup-Accessory-Sign-Info";
pub(crate) const PAIR_VERIFY_ENCRYPT_SALT: &[u8] = b"Pair-Verify-Encrypt-Salt";
pub(crate) const PAIR_VERIFY_ENCRYPT_INFO: &[u8] = b"Pair-Verify-Encrypt-Info";
pub(crate) const CONTROL_SALT: &[u8] = b"Control-Salt";
pub(crate) const CONTROL_WRITE_KEY_INFO: &[u8] = b"Control-Write-Encryption-Key";
pub(crate) const CONTROL_READ_KEY_INFO: &[u8] = b"Control-Read-Encryption-Key";
