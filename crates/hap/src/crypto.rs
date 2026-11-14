//! Small wrappers over the audited primitives HomeKit pairing needs.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha512;

/// Cryptographically secure random bytes from the operating system.
pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("operating system random source failed");
    out
}

/// HKDF-SHA512 producing a 32-byte key.
pub fn hkdf(salt: &[u8], info: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA512 output length");
    out
}

/// HomeKit nonces are 12 bytes: four zero bytes followed by eight caller bytes.
fn nonce(tail: &[u8; 8]) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(tail);
    Nonce::from(n)
}

/// ChaCha20-Poly1305 encrypt. Returns ciphertext with the 16-byte tag appended.
pub fn seal(key: &[u8; 32], nonce_tail: &[u8; 8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&nonce(nonce_tail), Payload { msg: plaintext, aad })
        .expect("ChaCha20-Poly1305 encryption cannot fail for these sizes")
}

/// ChaCha20-Poly1305 decrypt. `None` if authentication fails.
pub fn open(key: &[u8; 32], nonce_tail: &[u8; 8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&nonce(nonce_tail), Payload { msg: sealed, aad })
        .ok()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| n << 8 | *b as u32) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(BASE64[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let digits = text.trim_end_matches('=').as_bytes();
    // Padding only ever stands in for one or two missing characters.
    if !text.len().is_multiple_of(4) || text.len() - digits.len() > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() * 3 / 4);
    let (mut bits, mut count) = (0u32, 0u8);
    for digit in digits {
        let value = BASE64.iter().position(|c| c == digit)? as u32;
        bits = bits << 6 | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_rejects_garbage() {
        for (plain, encoded) in [("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg==")] {
            assert_eq!(base64_encode(plain.as_bytes()), encoded);
            assert_eq!(base64_decode(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("Zg=").is_none());
        assert!(base64_decode("Z!==").is_none());
        assert!(base64_decode("====").is_none());
    }

    #[test]
    fn seal_open_round_trip_and_tamper() {
        let key = random::<32>();
        let sealed = seal(&key, b"PS-Msg05", b"aad", b"hello");
        assert_eq!(open(&key, b"PS-Msg05", b"aad", &sealed).unwrap(), b"hello");
        assert!(open(&key, b"PS-Msg06", b"aad", &sealed).is_none());
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(open(&key, b"PS-Msg05", b"aad", &bad).is_none());
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(from_hex(&to_hex(&[0, 255, 16])).unwrap(), vec![0, 255, 16]);
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }
}
