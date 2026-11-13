//! The owner's choices about each UniFi Protect device: whether it is shared
//! with HomeKit, and the name it is published under.
//!
//! The choices are made in the terminal interface, kept in `devices.json`
//! in the state directory, and applied by the Protect bridge each time it
//! works out which accessories to publish.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use serde::{Deserialize, Serialize};

use crate::protect_bridge::{Detection, DeviceDef};

const FILE_NAME: &str = "devices.json";
/// Where the prefix and suffix chosen in the dashboard are kept.
const NAMES_FILE: &str = "names.json";
/// Where the recognition sensors chosen for every camera are kept.
const DETECTION_FILE: &str = "detection.json";
/// Longest prefix or suffix accepted, as for `config.toml`.
pub const MAX_AFFIX: usize = 24;
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
    /// What the device can recognise, as last seen.
    #[serde(skip)]
    pub detects: Vec<Detection>,
    /// The recognition sensors chosen for this device in particular, on
    /// top of those chosen for every camera.
    pub sensors: BTreeSet<Detection>,
}

impl Entry {
    /// The name the device goes by here.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.protect_name)
    }

    fn is_default(&self) -> bool {
        !self.hidden && self.name.is_none() && self.sensors.is_empty()
    }
}

/// The text put before and after every name sent to HomeKit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct Affix {
    /// What was chosen in the dashboard. Absent means `config.toml` decides.
    prefix: Option<String>,
    suffix: Option<String>,
    /// What `config.toml` says, which is never written back.
    #[serde(skip)]
    default: (String, String),
}

/// The recognition sensors published for every camera that can tell.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct Everywhere {
    all: BTreeSet<Detection>,
}

/// Which end of the name a piece of text goes on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Prefix,
    Suffix,
}

pub struct Overrides {
    /// Where the choices are kept, if anywhere.
    path: Option<PathBuf>,
    affix: Mutex<Affix>,
    everywhere: Mutex<Everywhere>,
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
    match def.lens {
        0 => format!("protect:{kind}:{}", def.id),
        // A camera's second lens is an accessory of its own.
        lens => format!("protect:{kind}:{}:lens{lens}", def.id),
    }
}

/// Notes the prefix and suffix `config.toml` asks for, and returns the ones
/// to use: those chosen in the dashboard, where any were.
pub fn affix_from(prefix: &str, suffix: &str) -> (String, String) {
    match global() {
        Some(overrides) => overrides.affix_from(prefix, suffix),
        None => (prefix.to_owned(), suffix.to_owned()),
    }
}

/// The prefix and suffix now in force, if choices are loaded.
pub fn affix() -> Option<(String, String)> {
    global().map(Overrides::affix)
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

/// Replaces a file in one step with one only its owner can read.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension("json.tmp");
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)
}

impl Overrides {
    /// Choices that are kept only in memory.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            affix: Mutex::new(Affix::default()),
            everywhere: Mutex::new(Everywhere::default()),
            entries: Mutex::new(BTreeMap::new()),
            changed: AtomicBool::new(false),
        }
    }

    fn lock_affix(&self) -> MutexGuard<'_, Affix> {
        self.affix.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn affix_from(&self, prefix: &str, suffix: &str) -> (String, String) {
        self.lock_affix().default = (prefix.to_owned(), suffix.to_owned());
        self.affix()
    }

    pub fn affix(&self) -> (String, String) {
        let affix = self.lock_affix();
        (
            affix.prefix.clone().unwrap_or_else(|| affix.default.0.clone()),
            affix.suffix.clone().unwrap_or_else(|| affix.default.1.clone()),
        )
    }

    /// Sets the text put before or after every name sent to HomeKit, or
    /// with `None` goes back to what `config.toml` says. Returns the prefix
    /// and suffix now in force, or why nothing was changed.
    pub fn set_affix(&self, end: End, text: Option<&str>) -> Result<(String, String), String> {
        let what = if end == End::Prefix { "prefix" } else { "suffix" };
        if let Some(text) = text {
            // The same limits as for `config.toml`.
            if text.chars().count() > MAX_AFFIX {
                return Err(format!("a name {what} can be at most {MAX_AFFIX} characters"));
            }
            if text.chars().any(char::is_control) {
                return Err(format!("a name {what} cannot contain control characters"));
            }
        }
        let mut affix = self.lock_affix();
        let before = affix.clone();
        let slot = if end == End::Prefix { &mut affix.prefix } else { &mut affix.suffix };
        *slot = text.map(str::to_owned);
        if *affix != before {
            let saved = match &self.path {
                Some(path) => serde_json::to_vec_pretty(&*affix)
                    .map_err(std::io::Error::other)
                    .and_then(|bytes| write_private(&path.with_file_name(NAMES_FILE), &bytes))
                    .map_err(|e| format!("could not save {NAMES_FILE}: {e}")),
                None => Ok(()),
            };
            if let Err(e) = saved {
                *affix = before;
                return Err(e);
            }
            self.changed.store(true, Ordering::Relaxed);
        }
        drop(affix);
        Ok(self.affix())
    }

    pub fn load(path: PathBuf) -> Self {
        let entries = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!("ignoring unreadable {}: {e}", path.display());
                BTreeMap::new()
            }),
            Err(_) => BTreeMap::new(),
        };
        let names = path.with_file_name(NAMES_FILE);
        let affix = match std::fs::read(&names) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!("ignoring unreadable {}: {e}", names.display());
                Affix::default()
            }),
            Err(_) => Affix::default(),
        };
        let chosen = path.with_file_name(DETECTION_FILE);
        let everywhere = match std::fs::read(&chosen) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!("ignoring unreadable {}: {e}", chosen.display());
                Everywhere::default()
            }),
            Err(_) => Everywhere::default(),
        };
        Self {
            path: Some(path),
            affix: Mutex::new(affix),
            everywhere: Mutex::new(everywhere),
            entries: Mutex::new(entries),
            changed: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Writes the devices that have a choice made about them; the rest need
    /// no record.
    fn save(&self, entries: &BTreeMap<String, Entry>) -> Result<(), String> {
        let Some(path) = &self.path else { return Ok(()) };
        let chosen: BTreeMap<&String, &Entry> = entries.iter().filter(|(_, e)| !e.is_default()).collect();
        serde_json::to_vec_pretty(&chosen)
            .map_err(std::io::Error::other)
            .and_then(|bytes| write_private(path, &bytes))
            .map_err(|e| format!("could not save {}: {e}", path.display()))
    }

    fn lock_everywhere(&self) -> MutexGuard<'_, Everywhere> {
        self.everywhere.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The recognition sensors published for every camera that can tell.
    pub fn sensors_everywhere(&self) -> Vec<Detection> {
        self.lock_everywhere().all.iter().copied().collect()
    }

    /// Publishes, or stops publishing, a sensor for one kind of thing
    /// cameras recognise: on the device with this key, or with no key on
    /// every camera that can tell. Returns the name of the device changed,
    /// if it was one, or why nothing was changed.
    pub fn set_sensor(&self, key: Option<&str>, detection: Detection, on: bool) -> Result<Option<String>, String> {
        let Some(key) = key else {
            let mut everywhere = self.lock_everywhere();
            let before = everywhere.clone();
            if on {
                everywhere.all.insert(detection);
            } else {
                everywhere.all.remove(&detection);
            }
            if *everywhere != before {
                let saved = match &self.path {
                    Some(path) => serde_json::to_vec_pretty(&*everywhere)
                        .map_err(std::io::Error::other)
                        .and_then(|bytes| write_private(&path.with_file_name(DETECTION_FILE), &bytes))
                        .map_err(|e| format!("could not save {DETECTION_FILE}: {e}")),
                    None => Ok(()),
                };
                if let Err(e) = saved {
                    *everywhere = before;
                    return Err(e);
                }
                self.changed.store(true, Ordering::Relaxed);
            }
            return Ok(None);
        };
        if on && self.lock().get(key).is_some_and(|entry| !entry.detects.contains(&detection)) {
            return Err(format!("that device does not recognise a {}", detection.word()));
        }
        let entry = self.change(key, |entry| {
            if on {
                entry.sensors.insert(detection);
            } else {
                entry.sensors.remove(&detection);
            }
        })?;
        Ok(Some(entry.display_name().to_owned()))
    }

    pub fn apply(&self, defs: Vec<DeviceDef>, fresh: bool) -> Vec<DeviceDef> {
        let everywhere = self.lock_everywhere().all.clone();
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
            entry.detects = def.features.detects.clone();
            def.features.sensors =
                def.features.detects.iter().copied().filter(|d| everywhere.contains(d) || entry.sensors.contains(d)).collect();
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

    #[test]
    fn a_second_lens_has_choices_of_its_own() {
        let mut lens = def(Kind::Camera, "cam1", "Front Door Package Camera");
        lens.lens = 2;
        assert_eq!(key(&lens), "protect:camera:cam1:lens2");
        let overrides = Overrides::in_memory();
        overrides.apply(vec![def(Kind::Camera, "cam1", "Front Door"), lens.clone()], true);
        overrides.set_shared("protect:camera:cam1:lens2", false).unwrap();
        let published = overrides.apply(vec![def(Kind::Camera, "cam1", "Front Door"), lens], true);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].lens, 0);
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
    fn recognition_sensors_are_chosen_for_every_camera_or_for_one() {
        let cameras = || {
            let mut front = def(Kind::Camera, "cam1", "Front Door");
            front.features.detects = vec![Detection::Person, Detection::Package];
            let mut yard = def(Kind::Camera, "cam2", "Yard");
            yard.features.detects = vec![Detection::Person, Detection::Vehicle];
            vec![front, yard]
        };
        let sensors = |overrides: &Overrides| -> Vec<Vec<Detection>> {
            overrides.apply(cameras(), true).into_iter().map(|def| def.features.sensors).collect()
        };
        let overrides = Overrides::in_memory();
        assert_eq!(sensors(&overrides), [vec![], vec![]], "none unless asked for");

        assert_eq!(overrides.set_sensor(None, Detection::Person, true), Ok(None));
        assert!(overrides.changed.swap(false, Ordering::Relaxed));
        assert_eq!(overrides.sensors_everywhere(), [Detection::Person]);
        assert_eq!(sensors(&overrides), [vec![Detection::Person], vec![Detection::Person]]);

        // One camera's own choice adds to what every camera has.
        assert_eq!(overrides.set_sensor(Some("protect:camera:cam1"), Detection::Package, true), Ok(Some("Front Door".into())));
        assert_eq!(sensors(&overrides), [vec![Detection::Person, Detection::Package], vec![Detection::Person]]);
        // A camera cannot have a sensor for what it does not recognise.
        assert!(overrides.set_sensor(Some("protect:camera:cam2"), Detection::Package, true).is_err());
        assert!(overrides.set_sensor(Some("protect:camera:nope"), Detection::Person, true).is_err());

        overrides.set_sensor(None, Detection::Person, false).unwrap();
        assert_eq!(sensors(&overrides), [vec![Detection::Package], vec![]]);
        overrides.set_sensor(Some("protect:camera:cam1"), Detection::Package, false).unwrap();
        assert_eq!(sensors(&overrides), [vec![], vec![]]);
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
    fn prefix_and_suffix_default_to_the_config_and_keep_its_limits() {
        let overrides = Overrides::in_memory();
        assert_eq!(overrides.affix(), (String::new(), String::new()));
        assert_eq!(overrides.affix_from("HM ", ""), ("HM ".to_owned(), String::new()), "the config decides at first");
        assert!(!overrides.changed.load(Ordering::Relaxed));

        // Spaces are kept exactly: they are what separates the name.
        assert_eq!(overrides.set_affix(End::Suffix, Some(" (UP)")).unwrap(), ("HM ".to_owned(), " (UP)".to_owned()));
        assert!(overrides.changed.swap(false, Ordering::Relaxed));
        // An empty prefix is a choice too, and overrides the config.
        assert_eq!(overrides.set_affix(End::Prefix, Some("")).unwrap().0, "");
        // Going back to the config's.
        assert_eq!(overrides.set_affix(End::Prefix, None).unwrap().0, "HM ");

        overrides.changed.store(false, Ordering::Relaxed);
        assert!(overrides.set_affix(End::Prefix, Some(&"x".repeat(MAX_AFFIX + 1))).is_err());
        assert!(overrides.set_affix(End::Suffix, Some("a\tb")).is_err());
        assert_eq!(overrides.set_affix(End::Suffix, Some(" (UP)")).unwrap().1, " (UP)", "unchanged");
        assert!(!overrides.changed.load(Ordering::Relaxed), "refused and unchanged settings disturb nothing");
        assert!(overrides.set_affix(End::Prefix, Some(&"é".repeat(MAX_AFFIX))).is_ok(), "characters, not bytes");
    }

    #[test]
    fn prefix_and_suffix_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("hm-overrides-names-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let overrides = Overrides::load(dir.join(FILE_NAME));
        overrides.affix_from("HM ", " cfg");
        overrides.set_affix(End::Prefix, Some("UP ")).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let names = dir.join(NAMES_FILE);
        assert_eq!(std::fs::metadata(&names).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!std::fs::read_to_string(&names).unwrap().contains("cfg"), "the config's values are not copied");

        let reloaded = Overrides::load(dir.join(FILE_NAME));
        // The chosen prefix holds; the suffix still follows the config, even if that changes.
        assert_eq!(reloaded.affix_from("HM ", " new"), ("UP ".to_owned(), " new".to_owned()));
        let _ = std::fs::remove_dir_all(&dir);
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
