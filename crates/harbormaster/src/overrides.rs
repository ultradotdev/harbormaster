//! The owner's choices about each UniFi Protect device: whether it is shared
//! with HomeKit, and the name it is published under.
//!
//! The choices are made in the terminal interface, kept in `devices.json`
//! in the state directory, and applied by the Protect bridge each time it
//! works out which accessories to publish.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use serde::{Deserialize, Serialize};

use crate::protect_bridge::DeviceDef;

const FILE_NAME: &str = "devices.json";
/// Longest name accepted for a device.
pub const MAX_NAME: usize = 64;

/// What is known and chosen about one device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    /// Not shared with HomeKit.
    pub hidden: bool,
    /// The name to publish instead of the one Protect gives.
    pub name: Option<String>,
    /// The device's name in Protect, as last seen.
    pub protect_name: String,
    /// "camera", "sensor" or "light".
    pub kind: String,
}

impl Entry {
    /// The name the device goes by here.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.protect_name)
    }

    fn is_default(&self) -> bool {
        !self.hidden && self.name.is_none()
    }
}

pub struct Overrides {
    /// Where the choices are kept, if anywhere.
    path: Option<PathBuf>,
    entries: Mutex<BTreeMap<String, Entry>>,
    /// Set when a choice changed and the bridge has yet to act on it.
    changed: AtomicBool,
}

static GLOBAL: OnceLock<Overrides> = OnceLock::new();

/// Loads the choices for this process. Call once, before the bridge starts.
pub fn init(state_dir: &Path) {
    let _ = GLOBAL.set(Overrides::load(state_dir.join(FILE_NAME)));
}

pub fn global() -> Option<&'static Overrides> {
    GLOBAL.get()
}

/// The key a device's choices are kept under, which is also the key of its
/// stable accessory id in the HomeKit store.
pub fn key(def: &DeviceDef) -> String {
    let kind = serde_json::to_value(def.kind).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
    format!("protect:{kind}:{}", def.id)
}

/// Drops devices that are not shared and applies chosen names. `fresh` says
/// the definitions came straight from the console, so their names are
/// Protect's own. Without choices loaded, everything passes unchanged.
pub fn apply(defs: Vec<DeviceDef>, fresh: bool) -> Vec<DeviceDef> {
    match global() {
        Some(overrides) => overrides.apply(defs, fresh),
        None => defs,
    }
}

/// Whether the owner has chosen not to share this device.
pub fn hidden(def: &DeviceDef) -> bool {
    global().is_some_and(|overrides| overrides.is_hidden(&key(def)))
}

/// Whether a choice changed since this was last asked.
pub fn take_changed() -> bool {
    global().is_some_and(|overrides| overrides.changed.swap(false, Ordering::Relaxed))
}

impl Overrides {
    /// Choices that are kept only in memory.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self { path: None, entries: Mutex::new(BTreeMap::new()), changed: AtomicBool::new(false) }
    }

    pub fn load(path: PathBuf) -> Self {
        let entries = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!("ignoring unreadable {}: {e}", path.display());
                BTreeMap::new()
            }),
            Err(_) => BTreeMap::new(),
        };
        Self { path: Some(path), entries: Mutex::new(entries), changed: AtomicBool::new(false) }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Writes the devices that have a choice made about them; the rest need
    /// no record.
    fn save(&self, entries: &BTreeMap<String, Entry>) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let Some(path) = &self.path else { return Ok(()) };
        let chosen: BTreeMap<&String, &Entry> = entries.iter().filter(|(_, e)| !e.is_default()).collect();
        let temporary = path.with_extension("json.tmp");
        serde_json::to_vec_pretty(&chosen)
            .map_err(std::io::Error::other)
            .and_then(|bytes| {
                let mut file =
                    std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temporary)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                std::fs::rename(&temporary, path)
            })
            .map_err(|e| format!("could not save {}: {e}", path.display()))
    }

    pub fn apply(&self, defs: Vec<DeviceDef>, fresh: bool) -> Vec<DeviceDef> {
        let mut entries = self.lock();
        let mut out = Vec::new();
        for mut def in defs {
            let entry = entries.entry(key(&def)).or_default();
            // Definitions remembered from the last run may already carry a
            // chosen name, so only the console's word is taken for Protect's.
            if fresh || entry.protect_name.is_empty() && entry.name.is_none() {
                entry.protect_name = def.name.clone();
            }
            entry.kind = key(&def).split(':').nth(1).unwrap_or_default().to_owned();
            if entry.hidden {
                continue;
            }
            if let Some(name) = &entry.name {
                def.name = name.clone();
            }
            out.push(def);
        }
        out
    }

    pub fn is_hidden(&self, key: &str) -> bool {
        self.lock().get(key).is_some_and(|e| e.hidden)
    }

    /// Every device seen or chosen about, by key.
    pub fn list(&self) -> Vec<(String, Entry)> {
        self.lock().iter().map(|(k, e)| (k.clone(), e.clone())).collect()
    }

    /// Makes one change to a known device and saves it. Returns the entry
    /// as it now stands, or why nothing was changed.
    fn change(&self, key: &str, change: impl FnOnce(&mut Entry)) -> Result<Entry, String> {
        let mut entries = self.lock();
        let Some(entry) = entries.get_mut(key) else {
            return Err(format!("no UniFi Protect device is known as {key}"));
        };
        let before = entry.clone();
        change(entry);
        let after = entry.clone();
        if after != before {
            if let Err(e) = self.save(&entries) {
                // Nothing is changed that would not survive a restart.
                entries.insert(key.to_owned(), before);
                return Err(e);
            }
            self.changed.store(true, Ordering::Relaxed);
        }
        Ok(after)
    }

    /// Shares a device with HomeKit, or stops sharing it.
    pub fn set_shared(&self, key: &str, shared: bool) -> Result<Entry, String> {
        self.change(key, |entry| entry.hidden = !shared)
    }

    /// Publishes a device under `name`, or under Protect's own name again
    /// if `name` is absent or blank.
    pub fn rename(&self, key: &str, name: Option<&str>) -> Result<Entry, String> {
        let name = name.map(str::trim).filter(|n| !n.is_empty());
        if let Some(name) = name {
            if name.chars().count() > MAX_NAME {
                return Err(format!("a name can be at most {MAX_NAME} characters"));
            }
            if name.chars().any(char::is_control) {
                return Err("a name cannot contain control characters".to_owned());
            }
        }
        self.change(key, |entry| {
            // Choosing Protect's own name is the same as choosing none.
            entry.name = name.filter(|n| *n != entry.protect_name).map(str::to_owned);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protect_bridge::{Features, Kind};

    fn def(kind: Kind, id: &str, name: &str) -> DeviceDef {
        DeviceDef {
            kind,
            id: id.into(),
            name: name.into(),
            model: "m".into(),
            mac: "AA".into(),
            firmware: "1".into(),
            features: Features::default(),
            video: None,
            lens: 0,
        }
    }

    fn inventory() -> Vec<DeviceDef> {
        vec![def(Kind::Camera, "cam1", "Front Door"), def(Kind::Sensor, "sen1", "Yard")]
    }

    #[test]
    fn hidden_devices_are_dropped_and_names_replaced() {
        let overrides = Overrides::in_memory();
        assert_eq!(overrides.apply(inventory(), true), inventory(), "no choices, no change");
        assert!(!overrides.changed.load(Ordering::Relaxed));

        assert!(overrides.set_shared("protect:camera:cam1", false).unwrap().hidden);
        overrides.rename("protect:sensor:sen1", Some("  Back Yard ")).unwrap();
        assert!(overrides.changed.swap(false, Ordering::Relaxed));
        let published = overrides.apply(inventory(), true);
        assert_eq!(published.len(), 1);
        assert_eq!((published[0].id.as_str(), published[0].name.as_str()), ("sen1", "Back Yard"));
        assert!(overrides.is_hidden("protect:camera:cam1"));

        // Sharing again and clearing the name restore the original.
        overrides.set_shared("protect:camera:cam1", true).unwrap();
        overrides.rename("protect:sensor:sen1", None).unwrap();
        assert_eq!(overrides.apply(inventory(), true), inventory());
        // Choosing Protect's own name is no choice at all.
        assert_eq!(overrides.rename("protect:sensor:sen1", Some("Yard")).unwrap().name, None);
    }

    #[test]
    fn unknown_devices_and_bad_names_are_refused() {
        let overrides = Overrides::in_memory();
        overrides.apply(inventory(), true);
        assert!(overrides.set_shared("protect:camera:nope", false).is_err());
        assert!(overrides.rename("protect:camera:cam1", Some(&"x".repeat(MAX_NAME + 1))).is_err());
        assert!(overrides.rename("protect:camera:cam1", Some("a\nb")).is_err());
        assert!(!overrides.changed.load(Ordering::Relaxed), "a refused change is no change");
        // A change that changes nothing does not disturb the bridge either.
        overrides.set_shared("protect:camera:cam1", true).unwrap();
        assert!(!overrides.changed.load(Ordering::Relaxed));
    }

    #[test]
    fn choices_survive_a_restart_and_keep_protects_name() {
        let dir = std::env::temp_dir().join(format!("hm-overrides-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        let overrides = Overrides::load(path.clone());
        overrides.apply(inventory(), true);
        overrides.set_shared("protect:camera:cam1", false).unwrap();
        overrides.rename("protect:sensor:sen1", Some("Back Yard")).unwrap();

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        let reloaded = Overrides::load(path);
        // The last run's definitions carry the chosen name, not Protect's.
        let cached = vec![def(Kind::Sensor, "sen1", "Back Yard")];
        assert_eq!(reloaded.apply(cached, false)[0].name, "Back Yard");
        let entries: BTreeMap<String, Entry> = reloaded.list().into_iter().collect();
        assert_eq!(entries["protect:sensor:sen1"].protect_name, "Yard");
        assert_eq!(entries["protect:sensor:sen1"].display_name(), "Back Yard");
        // A hidden device is still known, so it can be shared again.
        assert!(entries["protect:camera:cam1"].hidden);
        assert_eq!((entries["protect:camera:cam1"].display_name(), entries["protect:camera:cam1"].kind.as_str()), ("Front Door", "camera"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
