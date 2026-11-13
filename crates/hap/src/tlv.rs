//! TLV8 encoding used by the HomeKit pairing endpoints.
//!
//! Each item is `type (1 byte) | length (1 byte) | value`. Values longer than
//! 255 bytes are split into consecutive fragments of the same type.

pub const METHOD: u8 = 0x00;
pub const IDENTIFIER: u8 = 0x01;
pub const SALT: u8 = 0x02;
pub const PUBLIC_KEY: u8 = 0x03;
pub const PROOF: u8 = 0x04;
pub const ENCRYPTED_DATA: u8 = 0x05;
pub const STATE: u8 = 0x06;
pub const ERROR: u8 = 0x07;
pub const SIGNATURE: u8 = 0x0A;
pub const PERMISSIONS: u8 = 0x0B;
pub const SEPARATOR: u8 = 0xFF;

/// Pairing error codes carried in the `ERROR` item.
pub mod error {
    pub const UNKNOWN: u8 = 0x01;
    pub const AUTHENTICATION: u8 = 0x02;
    pub const MAX_TRIES: u8 = 0x05;
    pub const UNAVAILABLE: u8 = 0x06;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tlv(Vec<(u8, Vec<u8>)>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("truncated TLV8 data")]
pub struct Truncated;

impl Tlv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, ty: u8, value: &[u8]) -> Self {
        self.push(ty, value);
        self
    }

    pub fn push(&mut self, ty: u8, value: &[u8]) {
        self.0.push((ty, value.to_vec()));
    }

    /// First item of the given type.
    pub fn get(&self, ty: u8) -> Option<&[u8]> {
        self.0.iter().find(|(t, _)| *t == ty).map(|(_, v)| v.as_slice())
    }

    pub fn get_u8(&self, ty: u8) -> Option<u8> {
        match self.get(ty) {
            Some([b]) => Some(*b),
            _ => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (ty, value) in &self.0 {
            if value.is_empty() {
                out.extend_from_slice(&[*ty, 0]);
                continue;
            }
            for chunk in value.chunks(255) {
                out.push(*ty);
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    pub fn decode(mut data: &[u8]) -> Result<Self, Truncated> {
        let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
        // True while the previous fragment was full (255 bytes), meaning a
        // following item of the same type continues it.
        let mut continuing = false;
        while !data.is_empty() {
            if data.len() < 2 {
                return Err(Truncated);
            }
            let (ty, len) = (data[0], data[1] as usize);
            if data.len() < 2 + len {
                return Err(Truncated);
            }
            let value = &data[2..2 + len];
            match items.last_mut() {
                Some((last_ty, last)) if continuing && *last_ty == ty => {
                    last.extend_from_slice(value)
                }
                _ => items.push((ty, value.to_vec())),
            }
            continuing = len == 255;
            data = &data[2 + len..];
        }
        Ok(Self(items))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_long_values() {
        let long = vec![7u8; 600];
        let tlv = Tlv::new().with(STATE, &[2]).with(PUBLIC_KEY, &long).with(SALT, &[1, 2]);
        let bytes = tlv.encode();
        // 600 bytes become fragments of 255 + 255 + 90.
        assert_eq!(bytes.len(), 3 + (2 + 255) * 2 + (2 + 90) + 4);
        assert_eq!(Tlv::decode(&bytes).unwrap(), tlv);
    }

    #[test]
    fn exact_255_does_not_merge_into_separate_item() {
        let tlv = Tlv::new().with(SALT, &[1u8; 255]).with(SEPARATOR, &[]).with(SALT, &[2]);
        assert_eq!(Tlv::decode(&tlv.encode()).unwrap(), tlv);
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(Tlv::decode(&[STATE, 2, 1]), Err(Truncated));
        assert_eq!(Tlv::decode(&[STATE]), Err(Truncated));
    }
}
