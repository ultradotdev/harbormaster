//! Persistent bridge identity and pairings.
//!
//! One JSON file, written atomically with owner-only permissions. Losing or
//! regenerating this file forces every controller to re-pair, so it is only
//! ever created when absent, never silently replaced.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::crypto::{from_hex, random, to_hex};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("state file {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("state file {0} is corrupt: {1}")]
    Corrupt(PathBuf, String),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Pairing {
    /// Controller long-term public key, hex.
    pub public_key: String,
    pub admin: bool,
}

#[derive(Serialize, Deserialize)]
struct State {
    /// Accessory pairing identifier, formatted like a MAC address.
    device_id: String,
    setup_code: String,
    /// Four-character id that ties a scanned QR code to this bridge.
    #[serde(default)]
    setup_id: String,
    /// Accessory long-term Ed25519 secret key, hex.
    secret_key: String,
    /// Bumped whenever the accessory database changes shape.
    config_number: u32,
    pairings: BTreeMap<String, Pairing>,
    /// Stable accessory ids keyed by an integration-chosen device key.
    #[serde(default)]
    accessory_ids: BTreeMap<String, u64>,
}

pub struct Store {
    path: PathBuf,
    state: Mutex<State>,
}

fn new_setup_id() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    // 252 is the largest multiple of 36 below 256, so the modulo is unbiased.
    random::<64>()
        .iter()
        .filter(|b| **b < 252)
        .take(4)
        .map(|b| char::from(ALPHABET[(*b % 36) as usize]))
        .collect()
}

fn base36(mut value: u64, width: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut digits = Vec::new();
    while value > 0 {
        digits.push(ALPHABET[(value % 36) as usize]);
        value /= 36;
    }
    while digits.len() < width {
        digits.push(b'0');
    }
    digits.iter().rev().map(|d| char::from(*d)).collect()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| n << 8 | *b as u32) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The payload of a HomeKit setup QR code: the setup code, an "IP accessory"
/// flag and the accessory category packed into a base-36 number, followed by
/// the setup id.
fn setup_uri(setup_code: &str, setup_id: &str, category: u8) -> String {
    const IP_ACCESSORY: u64 = 1 << 28;
    let code: u64 = setup_code.replace('-', "").parse().expect("setup code is numeric");
    format!("X-HM://{}{setup_id}", base36(code | IP_ACCESSORY | (category as u64) << 31, 9))
}

fn new_setup_code() -> String {
    // Codes Apple rejects as too guessable.
    const BANNED: [&str; 12] = [
        "00000000", "11111111", "22222222", "33333333", "44444444", "55555555", "66666666",
        "77777777", "88888888", "99999999", "12345678", "87654321",
    ];
    loop {
        // Rejection sampling keeps every digit uniformly distributed.
        let digits: String = random::<32>()
            .iter()
            .filter(|b| **b < 250)
            .take(8)
            .map(|b| char::from(b'0' + b % 10))
            .collect();
        if digits.len() == 8 && !BANNED.contains(&digits.as_str()) {
            return format!("{}-{}-{}", &digits[..3], &digits[3..5], &digits[5..]);
        }
    }
}

impl Store {
    /// Loads the state file, creating a fresh identity if it does not exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_owned();
        let state = match std::fs::read(&path) {
            Ok(bytes) => {
                let mut state: State = serde_json::from_slice(&bytes)
                    .map_err(|e| StoreError::Corrupt(path.clone(), e.to_string()))?;
                if from_hex(&state.secret_key).map(|k| k.len()) != Some(32) {
                    return Err(StoreError::Corrupt(path, "bad secret key".into()));
                }
                // State files written before setup ids existed.
                if state.setup_id.is_empty() {
                    state.setup_id = new_setup_id();
                }
                state
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = random::<6>();
                State {
                    device_id: id.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"),
                    setup_code: new_setup_code(),
                    setup_id: new_setup_id(),
                    secret_key: to_hex(&random::<32>()),
                    config_number: 1,
                    pairings: BTreeMap::new(),
                    accessory_ids: BTreeMap::new(),
                }
            }
            Err(e) => return Err(StoreError::Io(path, e)),
        };
        let store = Self { path, state: Mutex::new(state) };
        store.save(&store.state.lock().unwrap())?;
        Ok(store)
    }

    fn save(&self, state: &State) -> Result<(), StoreError> {
        let io = |e| StoreError::Io(self.path.clone(), e);
        let json = serde_json::to_vec_pretty(state).expect("state serializes");
        let tmp = self.path.with_extension("tmp");
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(io)?;
        file.write_all(&json).map_err(io)?;
        file.sync_all().map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(io)
    }

    fn update<T>(&self, f: impl FnOnce(&mut State) -> T) -> Result<T, StoreError> {
        let mut state = self.state.lock().unwrap();
        let out = f(&mut state);
        self.save(&state)?;
        Ok(out)
    }

    pub fn device_id(&self) -> String {
        self.state.lock().unwrap().device_id.clone()
    }

    pub fn setup_code(&self) -> String {
        self.state.lock().unwrap().setup_code.clone()
    }

    /// What a HomeKit setup QR code for this bridge must contain.
    pub fn setup_uri(&self, category: u8) -> String {
        let state = self.state.lock().unwrap();
        setup_uri(&state.setup_code, &state.setup_id, category)
    }

    /// Advertised so a controller that scanned the QR code can find the
    /// matching bridge without learning the setup code from the network.
    pub fn setup_hash(&self) -> String {
        use sha2::{Digest, Sha512};
        let state = self.state.lock().unwrap();
        let digest = Sha512::digest(format!("{}{}", state.setup_id, state.device_id));
        base64(&digest[..4])
    }

    pub fn config_number(&self) -> u32 {
        self.state.lock().unwrap().config_number
    }

    pub fn signing_key(&self) -> SigningKey {
        let bytes = from_hex(&self.state.lock().unwrap().secret_key).expect("validated on open");
        SigningKey::from_bytes(&bytes.try_into().expect("validated on open"))
    }

    pub fn is_paired(&self) -> bool {
        !self.state.lock().unwrap().pairings.is_empty()
    }

    pub fn pairing(&self, controller_id: &str) -> Option<Pairing> {
        self.state.lock().unwrap().pairings.get(controller_id).cloned()
    }

    pub fn pairings(&self) -> Vec<(String, Pairing)> {
        self.state.lock().unwrap().pairings.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub fn add_pairing(&self, id: &str, public_key: &[u8; 32], admin: bool) -> Result<(), StoreError> {
        self.update(|s| {
            s.pairings.insert(id.to_owned(), Pairing { public_key: to_hex(public_key), admin });
        })
    }

    /// Removes a pairing. When the last admin goes, every pairing goes with
    /// it, which returns the accessory to the unpaired state.
    pub fn remove_pairing(&self, id: &str) -> Result<(), StoreError> {
        self.update(|s| {
            s.pairings.remove(id);
            if !s.pairings.values().any(|p| p.admin) {
                s.pairings.clear();
            }
        })
    }

    /// Returns the stable accessory id for a device key, allocating the next
    /// free id (starting at 2, since 1 is the bridge) on first sight.
    pub fn accessory_id(&self, key: &str) -> Result<u64, StoreError> {
        if let Some(id) = self.state.lock().unwrap().accessory_ids.get(key) {
            return Ok(*id);
        }
        self.update(|s| {
            let next = s.accessory_ids.values().max().map_or(2, |m| m + 1);
            *s.accessory_ids.entry(key.to_owned()).or_insert(next)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hm-store-{}-{name}", to_hex(&random::<6>())));
        dir.join("state.json")
    }

    #[test]
    fn identity_and_ids_survive_reopen() {
        let path = temp_path("reopen");
        let store = Store::open(&path).unwrap();
        let (id, code, key) = (store.device_id(), store.setup_code(), store.signing_key().to_bytes());
        assert_eq!(store.accessory_id("tempest:1").unwrap(), 2);
        assert_eq!(store.accessory_id("ambient:1").unwrap(), 3);
        store.add_pairing("phone", &[1u8; 32], true).unwrap();
        drop(store);

        let store = Store::open(&path).unwrap();
        assert_eq!((store.device_id(), store.setup_code()), (id, code));
        assert_eq!(store.signing_key().to_bytes(), key);
        assert_eq!(store.accessory_id("tempest:1").unwrap(), 2);
        assert!(store.is_paired());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn removing_last_admin_unpairs_everyone() {
        let path = temp_path("admin");
        let store = Store::open(&path).unwrap();
        store.add_pairing("admin", &[1u8; 32], true).unwrap();
        store.add_pairing("guest", &[2u8; 32], false).unwrap();
        store.remove_pairing("admin").unwrap();
        assert!(!store.is_paired());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_reset() {
        let path = temp_path("corrupt");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(Store::open(&path), Err(StoreError::Corrupt(..))));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn setup_uri_matches_known_example() {
        // Published example: code 841-31-633, category 8 (switch), IP accessory.
        assert_eq!(setup_uri("841-31-633", "7OSX", 8), "X-HM://0081YCYEP7OSX");
    }

    #[test]
    fn base64_pads_correctly() {
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn setup_id_is_four_base36_characters() {
        let id = new_setup_id();
        assert_eq!(id.len(), 4);
        assert!(id.chars().all(|c| c.is_ascii_digit() || c.is_ascii_uppercase()));
    }

    #[test]
    fn setup_code_has_expected_shape() {
        let code = new_setup_code();
        assert_eq!(code.len(), 10);
        assert!(code.chars().enumerate().all(|(i, c)| if i == 3 || i == 6 { c == '-' } else { c.is_ascii_digit() }));
    }

    #[cfg(unix)]
    #[test]
    fn state_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("mode");
        Store::open(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
