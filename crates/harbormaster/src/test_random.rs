//! Stand-ins for secrets in tests, made afresh on every run.
//!
//! A test that needs a password, a key or a salt takes one from here
//! rather than writing one down, so that no value in the source can be
//! mistaken for a real secret, by a reader or by a code scanner.

use std::io::Read;

/// `N` bytes from the system's random source.
pub fn bytes<const N: usize>() -> [u8; N] {
    let mut read = Vec::new();
    std::fs::File::open("/dev/urandom").unwrap().take(N as u64).read_to_end(&mut read).unwrap();
    read.try_into().unwrap()
}

/// A random word of sixteen letters and digits, to stand for a password.
pub fn word() -> String {
    bytes::<8>().iter().map(|b| format!("{b:02x}")).collect()
}
