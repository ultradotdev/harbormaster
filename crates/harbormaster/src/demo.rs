//! A pretend set of UniFi Protect devices for `daemon --demo`, so the
//! dashboard can be tried without a console: a doorbell, cameras, a
//! floodlight and sensors that see motion, get watched and recorded, and
//! can be shared, unshared and renamed like real ones.
//!
//! Nothing here talks to a network or serves video. The accessories are
//! built the way the Protect bridge builds them, at the same instance ids.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use harbormaster_hap::model::kind;
use harbormaster_hap::recording::kind::{ACTIVE, CAMERA_RECORDING_MANAGEMENT};
use harbormaster_hap::recording::TRIGGER_MOTION;
use harbormaster_hap::{Accessory, Bridge, Characteristic, Database, Format, Info, Store};
use serde_json::{json, Value};

use crate::overrides::{self, Overrides};
use crate::protect_bridge::{DeviceDef, Features, Kind};
use crate::{recording, status, video};

/// Put before every pretend device's HomeKit name unless the owner chooses otherwise.
const PREFIX: &str = "HM ";

/// What the dashboard shows as the console's address.
pub const CONSOLE: &str = "demo console";

struct Fake {
    def: DeviceDef,
    doorbell: bool,
    online: bool,
    contact: bool,
    climate: bool,
    /// Charge in percent, and whether that counts as low.
    battery: Option<(u8, bool)>,
    tampered: bool,
    recording: bool,
}

fn fake(kind: Kind, id: &str, name: &str, model: &str) -> Fake {
    Fake {
        def: DeviceDef {
            kind,
            id: id.into(),
            name: name.into(),
            model: model.into(),
            mac: format!("DE{:0>10}", id.to_uppercase()),
            firmware: "1.0.0".into(),
            features: Features::default(),
            video: None,
            lens: 0,
        },
        doorbell: false,
        online: true,
        contact: false,
        climate: false,
        battery: None,
        tampered: false,
        recording: false,
    }
}

fn fleet() -> Vec<Fake> {
    vec![
        Fake { doorbell: true, recording: true, ..fake(Kind::Camera, "door", "Front Door", "G4 Doorbell Pro") },
        fake(Kind::Camera, "drive", "Driveway", "G5 Bullet"),
        Fake { online: false, ..fake(Kind::Camera, "garage", "Garage", "G5 Flex") },
        fake(Kind::Camera, "gate", "Side Gate", "G5 Flex"),
        fake(Kind::Light, "flood", "Floodlight", "UP FloodLight"),
        Fake { contact: true, battery: Some((96, false)), ..fake(Kind::Sensor, "back", "Back Door", "UP Sense") },
        Fake { climate: true, battery: Some((12, true)), tampered: true, ..fake(Kind::Sensor, "yard", "Yard", "UP Sense") },
    ]
}

fn build(aid: u64, f: &Fake, name: &str) -> Accessory {
    let mut accessory = Accessory::new(
        aid,
        &Info {
            name,
            manufacturer: "Ubiquiti",
            model: &f.def.model,
            serial_number: &f.def.mac,
            firmware_revision: &f.def.firmware,
        },
    );
    let active = || Characteristic::sensor(kind::STATUS_ACTIVE, Format::Bool, json!(f.online));
    let tamper =
        || Characteristic::sensor(kind::STATUS_TAMPERED, Format::Uint8, json!(u8::from(f.tampered))).range(0.0, 1.0, 1.0);
    if f.doorbell {
        let press =
            Characteristic::sensor(kind::PROGRAMMABLE_SWITCH_EVENT, Format::Uint8, Value::Null).range(0.0, 0.0, 1.0);
        accessory.add_service_at(110, kind::DOORBELL, true, vec![press]);
    }
    if f.contact {
        let state = Characteristic::sensor(kind::CONTACT_SENSOR_STATE, Format::Uint8, json!(0)).range(0.0, 1.0, 1.0);
        accessory.add_service_at(120, kind::CONTACT_SENSOR, true, vec![state, active(), tamper()]);
    }
    if f.def.kind != Kind::Sensor {
        let motion = Characteristic::sensor(kind::MOTION_DETECTED, Format::Bool, json!(false));
        accessory.add_service_at(100, kind::MOTION_SENSOR, !f.doorbell, vec![motion, active()]);
    }
    if f.climate {
        let temperature = Characteristic::sensor(kind::CURRENT_TEMPERATURE, Format::Float, json!(17.2))
            .unit("celsius")
            .range(-100.0, 100.0, 0.1);
        accessory.add_service_at(130, kind::TEMPERATURE_SENSOR, true, vec![temperature, active(), tamper()]);
        let humidity = Characteristic::sensor(kind::CURRENT_RELATIVE_HUMIDITY, Format::Float, json!(64.0))
            .unit("percentage")
            .range(0.0, 100.0, 1.0);
        accessory.add_service_at(140, kind::HUMIDITY_SENSOR, false, vec![humidity, active(), tamper()]);
    }
    if f.def.kind == Kind::Light {
        let on = Characteristic { writable: true, ..Characteristic::sensor(kind::ON, Format::Bool, json!(false)) };
        let level = Characteristic { writable: true, ..Characteristic::sensor(kind::BRIGHTNESS, Format::Int, json!(83)) }
            .unit("percentage")
            .range(0.0, 100.0, 1.0);
        accessory.add_service_at(180, kind::LIGHTBULB, false, vec![on, level]);
    }
    if f.def.kind == Kind::Camera {
        let offered = video::resolutions(1920, 1080);
        video::add_stream_service(&mut accessory, 200, &offered);
        recording::add_services(&mut accessory, 300, &offered, TRIGGER_MOTION, Some(100));
    }
    if let Some((percent, low)) = f.battery {
        accessory.add_service_at(
            170,
            kind::BATTERY,
            false,
            vec![
                Characteristic::sensor(kind::BATTERY_LEVEL, Format::Uint8, json!(percent))
                    .unit("percentage")
                    .range(0.0, 100.0, 1.0),
                Characteristic::constant(kind::CHARGING_STATE, Format::Uint8, json!(2)).range(0.0, 2.0, 1.0),
                Characteristic::sensor(kind::STATUS_LOW_BATTERY, Format::Uint8, json!(u8::from(low))).range(0.0, 1.0, 1.0),
            ],
        );
    }
    accessory
}

/// The instance id of one characteristic of an accessory, found by kind.
fn iid(db: &Database, aid: u64, service: &str, characteristic: &str) -> Option<u64> {
    let json = db.to_json();
    let accessory = json["accessories"].as_array()?.iter().find(|a| a["aid"] == aid)?;
    let service = accessory["services"].as_array()?.iter().find(|s| s["type"] == service)?;
    service["characteristics"].as_array()?.iter().find(|c| c["type"] == characteristic)?["iid"].as_u64()
}

fn set(db: &Database, aid: u64, service: &str, characteristic: &str, value: Value) {
    if let Some(iid) = iid(db, aid, service, characteristic) {
        db.set(aid, iid, value);
    }
}

pub struct Fleet {
    devices: Vec<(u64, Fake)>,
    db: Arc<Database>,
    choices: &'static Overrides,
    /// The plain name and the HomeKit name of each device now published,
    /// by device id.
    published: BTreeMap<String, (String, String)>,
}

impl Fleet {
    /// Publishes the pretend devices, honouring the owner's saved choices.
    /// Returns `None` if no choices are loaded to honour.
    pub fn publish(store: &Arc<Store>, db: &Arc<Database>) -> Result<Option<Self>> {
        let Some(choices) = overrides::global() else { return Ok(None) };
        let mut devices = Vec::new();
        for f in fleet() {
            devices.push((store.accessory_id(&overrides::key(&f.def))?, f));
        }
        let first_run = choices.list().is_empty();
        // The prefix a real site might use, to show how one looks.
        choices.affix_from(PREFIX, "");
        let mut fleet = Self { devices, db: db.clone(), choices, published: BTreeMap::new() };
        fleet.sync();
        if first_run {
            // Start with one device not shared, to show what that looks like.
            let _ = choices.set_shared("protect:camera:gate", false);
            overrides::take_changed();
            fleet.sync();
        }
        Ok(Some(fleet))
    }

    /// Makes the database match the owner's choices. Returns whether
    /// anything was added, removed or renamed.
    fn sync(&mut self) -> bool {
        let wanted = self.choices.apply(self.devices.iter().map(|(_, f)| f.def.clone()).collect(), true);
        let (prefix, suffix) = self.choices.affix();
        let mut changed = false;
        for (aid, f) in &self.devices {
            let name = wanted.iter().find(|d| d.id == f.def.id).map(|d| d.name.clone());
            // HomeKit gets the name with the prefix and suffix; the log and
            // the dashboard use the plain one.
            let shown = name.as_ref().map(|name| format!("{prefix}{name}{suffix}"));
            let old = self.published.get(&f.def.id).cloned();
            match (name, shown, old) {
                (None, _, Some((old, _))) => {
                    self.db.remove(*aid);
                    status::global().device_removed(*aid);
                    self.published.remove(&f.def.id);
                    tracing::info!("{old} is no longer shared with HomeKit");
                    changed = true;
                }
                (Some(name), Some(shown), old) if old.as_ref().map(|o| &o.1) != Some(&shown) => {
                    let name = name.as_str();
                    self.db.replace(build(*aid, f, &shown));
                    self.published.insert(f.def.id.clone(), (name.to_owned(), shown.clone()));
                    let kind = match f.def.kind {
                        Kind::Camera => "camera",
                        Kind::Light => "light",
                        Kind::Sensor => "sensor",
                    };
                    status::global().device_kind(*aid, kind, &overrides::key(&f.def));
                    if f.recording {
                        set(&self.db, *aid, CAMERA_RECORDING_MANAGEMENT, ACTIVE, json!(1));
                    }
                    if old.is_some() {
                        tracing::info!("{name}: HomeKit now knows it as {shown}");
                    }
                    changed = true;
                }
                _ => {}
            }
        }
        changed
    }

    /// The name a device currently goes by, if it is shared.
    fn shared(&self, id: &str) -> Option<(u64, String)> {
        let (aid, _) = self.devices.iter().find(|(_, f)| f.def.id == id)?;
        Some((*aid, self.published.get(id)?.0.clone()))
    }

    /// Acts out a household for ever: motion, a ring, someone watching, a
    /// recording, a light, and whatever the owner changes in the terminal.
    pub async fn run(mut self, bridge: Arc<Bridge>) {
        let board = status::global();
        let viewer: IpAddr = [10, 0, 0, 23].into();
        let (mut watching, mut recording) = (None, None);
        tracing::info!("connected to UniFi Protect at {CONSOLE} ({} devices)", self.devices.len());
        for second in 0u64..=u64::MAX {
            tokio::time::sleep(Duration::from_secs(1)).await;
            board.console_update();
            if overrides::take_changed() && self.sync() {
                bridge.republish();
            }
            let step = second % 60;
            if let Some((aid, name)) = self.shared("door") {
                match step {
                    5 => {
                        set(&self.db, aid, kind::MOTION_SENSOR, kind::MOTION_DETECTED, json!(true));
                        tracing::info!("{name}: motion detected");
                    }
                    8 => {
                        if let Some(iid) = iid(&self.db, aid, kind::DOORBELL, kind::PROGRAMMABLE_SWITCH_EVENT) {
                            self.db.emit(aid, iid, json!(0));
                        }
                        tracing::info!("doorbell ring: {name}");
                    }
                    9 => {
                        recording = Some(board.recording(&name));
                        tracing::info!("{name}: recording for HomeKit at 1600x1200, 2000 kbps, with sound, reaching back 8 s");
                    }
                    12 => {
                        watching = Some(board.viewing(aid, viewer, 1280, 720));
                        tracing::info!("{name}: streaming 1280x720 at 30 fps, 800 kbps, Opus sound at 16 kHz, 24 kbps to {viewer}");
                    }
                    28 => {
                        set(&self.db, aid, kind::MOTION_SENSOR, kind::MOTION_DETECTED, json!(false));
                        tracing::info!("{name}: motion ended");
                        if recording.take().is_some() {
                            tracing::info!("{name}: recording ended after 19 s and 5 pieces: the hub has what it wanted");
                        }
                    }
                    44 if watching.take().is_some() => {
                        tracing::info!("{name}: stream to {viewer} stopped after 32 s: the camera supplied 3100 kB; ffmpeg sent 960 frames, 2900 kB");
                    }
                    _ => {}
                }
            } else {
                (watching, recording) = (None, None);
            }
            if let Some((aid, name)) = self.shared("drive") {
                if matches!(step, 20 | 34) {
                    let seen = step == 20;
                    set(&self.db, aid, kind::MOTION_SENSOR, kind::MOTION_DETECTED, json!(seen));
                    tracing::info!("{name}: motion {}", if seen { "detected" } else { "ended" });
                }
            }
            if let Some((aid, _)) = self.shared("flood") {
                if matches!(step, 21 | 50) {
                    set(&self.db, aid, kind::LIGHTBULB, kind::ON, json!(step == 21));
                }
            }
            if let Some((aid, _)) = self.shared("back") {
                if matches!(step, 30 | 38) {
                    set(&self.db, aid, kind::CONTACT_SENSOR, kind::CONTACT_SENSOR_STATE, json!(u8::from(step == 30)));
                }
            }
            if let Some((aid, _)) = self.shared("yard") {
                let wave = (second % 40) as f64;
                let celsius = 15.0 + if wave < 20.0 { wave } else { 40.0 - wave } * 0.2;
                set(&self.db, aid, kind::TEMPERATURE_SENSOR, kind::CURRENT_TEMPERATURE, json!(celsius));
            }
            if let (55, Some((_, name))) = (step, self.shared("garage")) {
                tracing::warn!("{name}: could not open the live feed: the camera is not reachable");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretend_devices_are_built_like_real_ones() {
        for (n, f) in fleet().iter().enumerate() {
            let db = Database::new();
            db.add(build(n as u64 + 2, f, &f.def.name));
            let aid = n as u64 + 2;
            assert!(iid(&db, aid, kind::ACCESSORY_INFORMATION, kind::NAME).is_some());
            assert_eq!(iid(&db, aid, kind::MOTION_SENSOR, kind::MOTION_DETECTED).is_some(), f.def.kind != Kind::Sensor);
            assert_eq!(iid(&db, aid, CAMERA_RECORDING_MANAGEMENT, ACTIVE).is_some(), f.def.kind == Kind::Camera);
        }
    }
}
