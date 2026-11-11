//! Encrypted transport used after pair-verify succeeds.
//!
//! Each frame is `length (2 bytes LE) | ciphertext | tag (16 bytes)`, with the
//! length as associated data, at most 1024 plaintext bytes per frame, and a
//! per-direction message counter as the nonce.

use crate::crypto::{hkdf, open, seal};

const MAX_FRAME: usize = 1024;
const TAG: usize = 16;

pub struct Session {
    /// Controller-to-accessory key.
    read_key: [u8; 32],
    /// Accessory-to-controller key.
    write_key: [u8; 32],
    read_count: u64,
    write_count: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("encrypted frame failed authentication")]
pub struct BadFrame;

impl Session {
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        Self {
            read_key: hkdf(b"Control-Salt", b"Control-Write-Encryption-Key", shared_secret),
            write_key: hkdf(b"Control-Salt", b"Control-Read-Encryption-Key", shared_secret),
            read_count: 0,
            write_count: 0,
        }
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + (data.len() / MAX_FRAME + 1) * (2 + TAG));
        for chunk in data.chunks(MAX_FRAME) {
            let len = (chunk.len() as u16).to_le_bytes();
            out.extend_from_slice(&len);
            out.extend_from_slice(&seal(&self.write_key, &self.write_count.to_le_bytes(), &len, chunk));
            self.write_count += 1;
        }
        out
    }

    /// Moves every complete frame from `raw` into `plain`, leaving any
    /// trailing partial frame in `raw`.
    pub fn decrypt(&mut self, raw: &mut Vec<u8>, plain: &mut Vec<u8>) -> Result<(), BadFrame> {
        let mut pos = 0;
        while raw.len() - pos >= 2 {
            let len = u16::from_le_bytes([raw[pos], raw[pos + 1]]) as usize;
            if len > MAX_FRAME {
                return Err(BadFrame);
            }
            let end = pos + 2 + len + TAG;
            if raw.len() < end {
                break;
            }
            let frame = open(
                &self.read_key,
                &self.read_count.to_le_bytes(),
                &raw[pos..pos + 2],
                &raw[pos + 2..end],
            )
            .ok_or(BadFrame)?;
            plain.extend_from_slice(&frame);
            self.read_count += 1;
            pos = end;
        }
        raw.drain(..pos);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session with the directions swapped, standing in for the controller.
    fn peer(secret: &[u8; 32]) -> Session {
        let s = Session::new(secret);
        Session { read_key: s.write_key, write_key: s.read_key, read_count: 0, write_count: 0 }
    }

    #[test]
    fn large_message_round_trips_across_partial_reads() {
        let secret = [4u8; 32];
        let (mut accessory, mut controller) = (Session::new(&secret), peer(&secret));
        let message: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let wire = controller.encrypt(&message);

        let (mut raw, mut plain) = (Vec::new(), Vec::new());
        for piece in wire.chunks(700) {
            raw.extend_from_slice(piece);
            accessory.decrypt(&mut raw, &mut plain).unwrap();
        }
        assert!(raw.is_empty());
        assert_eq!(plain, message);
    }

    #[test]
    fn tampered_frame_is_rejected() {
        let secret = [4u8; 32];
        let (mut accessory, mut controller) = (Session::new(&secret), peer(&secret));
        let mut wire = controller.encrypt(b"GET /accessories HTTP/1.1\r\n\r\n");
        wire[5] ^= 1;
        assert!(accessory.decrypt(&mut wire, &mut Vec::new()).is_err());
    }
}
