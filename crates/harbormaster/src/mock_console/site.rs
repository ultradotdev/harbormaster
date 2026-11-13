//! The mock console's fictional site: its inventory, and a script of
//! things happening there that is played over and over.
//!
//! Everything here is invented. Addresses are from 192.0.2.0/24, which is
//! reserved for documentation, and hardware addresses are locally
//! administered ones that no real device carries.

use std::collections::HashMap;
use std::io::Write;

use serde_json::{json, Value};

pub const PORCH: &str = "6d6f636b0000000000000c01";
pub const DRIVEWAY: &str = "6d6f636b0000000000000c02";
pub const BACKYARD: &str = "6d6f636b0000000000000c03";
pub const GARAGE: &str = "6d6f636b0000000000000c04";
pub const FLOODLIGHT: &str = "6d6f636b0000000000000a01";
pub const BACK_DOOR: &str = "6d6f636b0000000000000b01";
pub const SHED: &str = "6d6f636b0000000000000b02";
pub const LAUNDRY: &str = "6d6f636b0000000000000b03";
pub const CHIME: &str = "6d6f636b0000000000000d01";

/// The lens a doorbell's package camera is filed under.
pub const PACKAGE_LENS: u8 = 2;

const FRAME_ACTION: u8 = 1;
const FRAME_DATA: u8 = 2;
const FORMAT_JSON: u8 = 1;

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// One stream of a camera, as the bootstrap lists it.
fn channel(id: u32, name: &str, width: u32, height: u32) -> Value {
    json!({
        "id": id, "name": name, "enabled": true, "width": width, "height": height,
        "fps": 15, "bitrate": 2_000_000, "isRtspEnabled": false
    })
}

fn camera(id: &str, mac: &str, ip: &str, name: &str, model: &str, market: &str, detects: &[&str]) -> Value {
    json!({
        "id": id, "mac": mac, "host": ip, "name": name, "type": model, "marketName": market,
        "modelKey": "camera", "state": "CONNECTED", "isAdopted": true, "isAdopting": false,
        "firmwareVersion": "4.0.0-mock", "videoCodec": "h264",
        "isMotionDetected": false, "isSmartDetected": false, "lastMotion": null, "lastRing": null,
        "isMicEnabled": true,
        "featureFlags": {
            "isDoorbell": false, "hasSmartDetect": !detects.is_empty(), "smartDetectTypes": detects,
            "hasSpeaker": false, "hasMic": true, "hasChime": false, "hasPackageCamera": false
        },
        "channels": [channel(0, "High", 1280, 720), channel(1, "Medium", 640, 360)],
        "lenses": []
    })
}

fn sensor(id: &str, mac: &str, name: &str, mount: &str) -> Value {
    json!({
        "id": id, "mac": mac, "name": name, "type": "UFP-SENSE", "marketName": "Mock Sensor",
        "modelKey": "sensor", "state": "CONNECTED", "isAdopted": true, "isAdopting": false,
        "firmwareVersion": "1.0.0-mock", "mountType": mount,
        "isOpened": false, "openStatusChangedAt": null, "leakDetectedAt": null, "tamperingDetectedAt": null,
        "batteryStatus": {"percentage": 88, "isLow": false},
        "stats": {"temperature": {"value": 19.5}, "humidity": {"value": 48}, "light": {"value": 120}},
        "motionSettings": {"isEnabled": false},
        "temperatureSettings": {"isEnabled": false},
        "humiditySettings": {"isEnabled": false},
        "lightSettings": {"isEnabled": false}
    })
}

/// The inventory the console starts with.
fn inventory() -> Value {
    let mut porch = camera(
        PORCH,
        "02AA00000C01",
        "192.0.2.21",
        "Front Porch",
        "UVC G4 Doorbell Pro",
        "G4 Doorbell Pro",
        &["person", "vehicle", "package"],
    );
    porch["featureFlags"]["isDoorbell"] = json!(true);
    porch["featureFlags"]["hasChime"] = json!(true);
    porch["featureFlags"]["hasSpeaker"] = json!(true);
    porch["featureFlags"]["hasPackageCamera"] = json!(true);
    porch["talkbackSettings"] = json!({"typeFmt": "aac", "samplingRate": 22050, "channels": 1});
    porch["lenses"] = json!([{"id": 0}, {"id": PACKAGE_LENS}]);
    porch["channels"] = json!([
        channel(0, "High", 1280, 960),
        channel(1, "Medium", 640, 480),
        channel(3, "Package Camera", 960, 720),
    ]);

    let mut shed = sensor(SHED, "02AA00000B02", "Garden Shed", "none");
    for setting in ["temperatureSettings", "humiditySettings", "lightSettings"] {
        shed[setting]["isEnabled"] = json!(true);
    }

    json!({
        "nvr": {
            "id": "6d6f636b0000000000000001", "mac": "02AA00000001", "host": "192.0.2.10",
            "name": "Mock Protect", "type": "UNVR", "marketName": "Mock NVR", "version": "6.0.0-mock",
            "modelKey": "nvr"
        },
        "cameras": [
            porch,
            camera(DRIVEWAY, "02AA00000C02", "192.0.2.22", "Driveway", "UVC G5 Bullet", "G5 Bullet", &["person", "vehicle"]),
            camera(BACKYARD, "02AA00000C03", "192.0.2.23", "Backyard", "UVC G5 Flex", "G5 Flex", &["person", "animal"]),
            camera(GARAGE, "02AA00000C04", "192.0.2.24", "Garage", "UVC G3 Instant", "G3 Instant", &[]),
        ],
        "lights": [{
            "id": FLOODLIGHT, "mac": "02AA00000A01", "host": "192.0.2.31", "name": "Side Yard Floodlight",
            "type": "UP FloodLight", "marketName": "Floodlight", "modelKey": "light",
            "state": "CONNECTED", "isAdopted": true, "isAdopting": false, "firmwareVersion": "1.0.0-mock",
            "isPirMotionDetected": false, "isLightOn": false, "lastMotion": null,
            "lightOnSettings": {"isLedForceOn": false},
            "lightDeviceSettings": {"ledLevel": 4}
        }],
        "sensors": [
            sensor(BACK_DOOR, "02AA00000B01", "Back Door", "door"),
            shed,
            sensor(LAUNDRY, "02AA00000B03", "Laundry Floor", "leak"),
        ],
        "chimes": [{
            "id": CHIME, "mac": "02AA00000D01", "name": "Hallway Chime", "type": "UP Chime",
            "marketName": "Chime", "modelKey": "chime", "state": "CONNECTED", "isAdopted": true
        }],
        "lastUpdateId": null
    })
}

/// The test picture each camera's lens shows, as an ffmpeg source.
pub fn pattern(camera: &str, lens: u8) -> &'static str {
    match (camera, lens) {
        (PORCH, 0) => "testsrc2",
        (PORCH, _) => "smptehdbars",
        (DRIVEWAY, _) => "testsrc",
        (BACKYARD, _) => "rgbtestsrc",
        _ => "yuvtestsrc",
    }
}

/// One frame of an update packet: an 8-byte header and a payload,
/// compressed as the real console usually sends it.
fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(payload).expect("writing to memory");
    let body = encoder.finish().expect("writing to memory");
    let mut out = vec![kind, FORMAT_JSON, 1, 0];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Recursively copies `changes` over `target`, as the console does when a
/// device changes.
fn merge(target: &mut Value, changes: &Value) {
    match (target, changes) {
        (Value::Object(target), Value::Object(changes)) => {
            for (key, value) in changes {
                merge(target.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        (target, changes) => *target = changes.clone(),
    }
}

/// The console's state, and the counter its updates are numbered by.
pub struct Site {
    doc: Value,
    serial: u64,
    /// Events in progress, by the camera they belong to.
    open_events: HashMap<String, String>,
}

impl Default for Site {
    fn default() -> Self {
        let mut site = Self { doc: inventory(), serial: 0, open_events: HashMap::new() };
        site.doc["lastUpdateId"] = json!(site.next_update_id());
        site
    }
}

impl Site {
    fn next_update_id(&mut self) -> String {
        self.serial += 1;
        format!("00000000-0000-4000-8000-{:012x}", self.serial)
    }

    pub fn bootstrap(&self) -> &Value {
        &self.doc
    }

    /// A device by its id, from the sections that hold devices.
    fn device_mut(&mut self, section: &str, id: &str) -> Option<&mut Value> {
        self.doc[section].as_array_mut()?.iter_mut().find(|d| d["id"] == id)
    }

    pub fn has_camera(&self, id: &str) -> bool {
        self.doc["cameras"].as_array().into_iter().flatten().any(|c| c["id"] == id)
    }

    /// Size of one of a camera's streams, by channel number.
    pub fn channel_size(&self, camera: &str, channel: u32) -> Option<(u32, u32)> {
        let camera = self.doc["cameras"].as_array()?.iter().find(|c| c["id"] == camera)?;
        let channel = camera["channels"].as_array()?.iter().find(|c| c["id"] == channel)?;
        Some((channel["width"].as_u64()? as u32, channel["height"].as_u64()? as u32))
    }

    /// The size of the package camera's single stream.
    pub fn package_size(&self, camera: &str) -> Option<(u32, u32)> {
        let camera = self.doc["cameras"].as_array()?.iter().find(|c| c["id"] == camera)?;
        let channel = camera["channels"].as_array()?.iter().find(|c| c["name"] == "Package Camera")?;
        Some((channel["width"].as_u64()? as u32, channel["height"].as_u64()? as u32))
    }

    fn packet(&mut self, action: &str, model_key: &str, id: &str, data: &Value) -> Vec<u8> {
        let header = json!({"action": action, "newUpdateId": self.next_update_id(), "modelKey": model_key, "id": id});
        self.doc["lastUpdateId"] = header["newUpdateId"].clone();
        let mut out = frame(FRAME_ACTION, header.to_string().as_bytes());
        out.extend(frame(FRAME_DATA, data.to_string().as_bytes()));
        out
    }

    /// Changes a device and returns the update that announces it.
    pub fn change(&mut self, model_key: &str, id: &str, data: Value) -> Option<Vec<u8>> {
        let section = section_of(model_key)?;
        merge(self.device_mut(section, id)?, &data);
        Some(self.packet("update", model_key, id, &data))
    }

    /// Announces an event, which is not part of the inventory.
    fn event(&mut self, action: &str, id: &str, data: Value) -> Vec<u8> {
        self.packet(action, "event", id, &data)
    }

    /// Applies a change asked for over the API, the way the console would,
    /// and returns the updates it causes.
    pub fn patch(&mut self, section: &str, id: &str, changes: &Value) -> Option<Vec<Vec<u8>>> {
        let model_key = model_key_of(section)?;
        let mut data = changes.clone();
        if model_key == "light" {
            // Forcing the light on turns it on; letting go turns it off
            // unless something is moving in front of it.
            if let Some(forced) = changes["lightOnSettings"]["isLedForceOn"].as_bool() {
                let moving = self.device_mut(section, id)?["isPirMotionDetected"] == true;
                data["isLightOn"] = json!(forced || moving);
            }
        }
        Some(vec![self.change(model_key, id, data)?])
    }
}

impl Site {
    /// A camera starts seeing something: an event begins, and the camera
    /// says it sees motion.
    fn begin_movement(&mut self, camera: &str, kinds: &[&str], now: u64, out: &mut Vec<Vec<u8>>) {
        let id = format!("6d6f636b{:016x}", self.serial + 1);
        let kind = if kinds.is_empty() { "motion" } else { "smartDetectZone" };
        out.push(self.event(
            "add",
            &id,
            json!({"type": kind, "camera": camera, "start": now, "end": null, "score": 80, "smartDetectTypes": kinds}),
        ));
        self.open_events.insert(camera.to_owned(), id);
        out.extend(self.change(
            "camera",
            camera,
            json!({"isMotionDetected": true, "isSmartDetected": !kinds.is_empty(), "lastMotion": now}),
        ));
    }
}

fn section_of(model_key: &str) -> Option<&'static str> {
    Some(match model_key {
        "camera" => "cameras",
        "light" => "lights",
        "sensor" => "sensors",
        "chime" => "chimes",
        _ => return None,
    })
}

fn model_key_of(section: &str) -> Option<&'static str> {
    Some(match section {
        "cameras" => "camera",
        "lights" => "light",
        "sensors" => "sensor",
        "chimes" => "chime",
        _ => return None,
    })
}

/// Something that happens at the site, with a beginning and an end.
#[derive(Clone, Copy, Debug)]
pub enum Scene {
    /// A camera recognises something.
    Detect(&'static str, &'static [&'static str]),
    /// A camera sees movement it does not recognise.
    Motion(&'static str),
    /// Someone rings the doorbell.
    Ring,
    /// The back door is opened and closed again.
    Door,
    /// Something walks past the floodlight.
    Floodlight,
    /// The shed's readings drift.
    Weather,
}

/// The order things happen in, repeated for as long as the mock runs.
pub const SCRIPT: [Scene; 9] = [
    Scene::Detect(DRIVEWAY, &["vehicle"]),
    Scene::Door,
    Scene::Detect(BACKYARD, &["animal"]),
    Scene::Ring,
    Scene::Detect(PORCH, &["person"]),
    Scene::Floodlight,
    Scene::Motion(GARAGE),
    Scene::Weather,
    Scene::Detect(PORCH, &["package"]),
];

fn name_of(camera: &str) -> &'static str {
    match camera {
        PORCH => "Front Porch",
        DRIVEWAY => "Driveway",
        BACKYARD => "Backyard",
        GARAGE => "Garage",
        _ => "a camera",
    }
}

impl Scene {
    /// What the log says when it begins.
    pub fn describe(self) -> String {
        match self {
            Scene::Detect(camera, kinds) => format!("{}: {} detected", name_of(camera), kinds.join(" and ")),
            Scene::Motion(camera) => format!("{}: motion", name_of(camera)),
            Scene::Ring => "Front Porch: doorbell rung".into(),
            Scene::Door => "Back Door: opened".into(),
            Scene::Floodlight => "Side Yard Floodlight: motion, light on".into(),
            Scene::Weather => "Garden Shed: new readings".into(),
        }
    }

    pub fn start(self, site: &mut Site, round: u64) -> Vec<Vec<u8>> {
        let now = now_ms();
        let mut out = Vec::new();
        match self {
            Scene::Detect(camera, kinds) => site.begin_movement(camera, kinds, now, &mut out),
            Scene::Motion(camera) => site.begin_movement(camera, &[], now, &mut out),
            Scene::Ring => {
                let id = format!("6d6f636b{:016x}", site.serial + 1);
                out.push(site.event("add", &id, json!({"type": "ring", "camera": PORCH, "start": now, "end": now})));
                out.extend(site.change("camera", PORCH, json!({"lastRing": now})));
            }
            Scene::Door => out.extend(site.change("sensor", BACK_DOOR, json!({"isOpened": true, "openStatusChangedAt": now}))),
            Scene::Floodlight => out.extend(site.change(
                "light",
                FLOODLIGHT,
                json!({"isPirMotionDetected": true, "isLightOn": true, "lastMotion": now}),
            )),
            Scene::Weather => {
                // A slow wobble, so the readings stay believable.
                let step = (round % 10) as f64;
                let stats = json!({
                    "temperature": {"value": 18.0 + step * 0.4},
                    "humidity": {"value": 45.0 + step},
                    "light": {"value": 80.0 + step * 25.0}
                });
                let battery = json!({"percentage": 88 - (round % 5), "isLow": false});
                out.extend(site.change("sensor", SHED, json!({"stats": stats, "batteryStatus": battery})));
            }
        }
        out
    }

    pub fn end(self, site: &mut Site) -> Vec<Vec<u8>> {
        let now = now_ms();
        let mut out = Vec::new();
        match self {
            Scene::Detect(camera, kinds) => {
                if let Some(id) = site.open_events.remove(camera) {
                    out.push(site.event("update", &id, json!({"end": now, "smartDetectTypes": kinds})));
                }
                out.extend(site.change("camera", camera, json!({"isMotionDetected": false, "isSmartDetected": false})));
            }
            Scene::Motion(camera) => {
                if let Some(id) = site.open_events.remove(camera) {
                    out.push(site.event("update", &id, json!({"end": now})));
                }
                out.extend(site.change("camera", camera, json!({"isMotionDetected": false})));
            }
            Scene::Door => out.extend(site.change("sensor", BACK_DOOR, json!({"isOpened": false, "openStatusChangedAt": now}))),
            Scene::Floodlight => {
                let forced = site.device_mut("lights", FLOODLIGHT).is_some_and(|l| l["lightOnSettings"]["isLedForceOn"] == true);
                out.extend(site.change("light", FLOODLIGHT, json!({"isPirMotionDetected": false, "isLightOn": forced})));
            }
            Scene::Ring | Scene::Weather => {}
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protect_bridge::{definitions, Detection, Kind};

    #[test]
    fn the_inventory_becomes_the_intended_accessories() {
        let site = Site::default();
        let defs = definitions(site.bootstrap());
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Front Porch",
                "Front Porch Package Camera",
                "Driveway",
                "Backyard",
                "Garage",
                "Back Door",
                "Garden Shed",
                "Laundry Floor",
                "Side Yard Floodlight"
            ]
        );
        let porch = &defs[0];
        assert!(porch.features.doorbell && porch.features.talk, "{porch:?}");
        assert_eq!(porch.features.detects, [Detection::Person, Detection::Vehicle, Detection::Package]);
        assert_eq!((defs[1].lens, defs[1].video), (PACKAGE_LENS, Some((960, 720))));
        assert_eq!(defs[3].features.detects, [Detection::Person, Detection::Animal]);
        assert!(defs[4].features.detects.is_empty() && defs[4].video == Some((1280, 720)));
        let shed = defs.iter().find(|d| d.name == "Garden Shed").unwrap();
        assert!(shed.features.temperature && shed.features.humidity && shed.features.light_level && shed.kind == Kind::Sensor);
        assert!(defs.iter().find(|d| d.name == "Back Door").unwrap().features.contact);
        assert!(defs.iter().find(|d| d.name == "Laundry Floor").unwrap().features.leak);
        // It must parse as the client's typed model as well.
        let typed: harbormaster_protect::model::Bootstrap = serde_json::from_value(site.bootstrap().clone()).unwrap();
        assert_eq!((typed.cameras.len(), typed.lights.len(), typed.sensors.len(), typed.chimes.len()), (4, 1, 3, 1));
    }

    #[test]
    fn every_scene_makes_updates_the_client_decodes() {
        let mut site = Site::default();
        let first = site.bootstrap()["lastUpdateId"].clone();
        let mut seen = Vec::new();
        for scene in SCRIPT {
            for packet in scene.start(&mut site, 3).into_iter().chain(scene.end(&mut site)) {
                let update = harbormaster_protect::decode_packet(&packet).unwrap();
                assert!(update.new_update_id.is_some(), "{update:?}");
                seen.push((update.model_key, update.action));
            }
        }
        assert_ne!(site.bootstrap()["lastUpdateId"], first);
        for wanted in [("event", "add"), ("event", "update"), ("camera", "update"), ("sensor", "update"), ("light", "update")] {
            assert!(seen.iter().any(|(m, a)| (m.as_str(), a.as_str()) == wanted), "no {wanted:?} in {seen:?}");
        }
        // Everything ends as it began, so the next round starts clean.
        let porch = &site.bootstrap()["cameras"][0];
        assert_eq!((porch["isMotionDetected"].clone(), porch["isSmartDetected"].clone()), (json!(false), json!(false)));
        assert!(site.open_events.is_empty());
    }

    #[test]
    fn forcing_the_floodlight_on_turns_it_on() {
        let mut site = Site::default();
        let updates = site.patch("lights", FLOODLIGHT, &json!({"lightOnSettings": {"isLedForceOn": true}})).unwrap();
        let update = harbormaster_protect::decode_packet(&updates[0]).unwrap();
        assert_eq!(update.data["isLightOn"], true);
        assert_eq!(site.bootstrap()["lights"][0]["isLightOn"], true);
        // The floodlight going quiet leaves a forced light on.
        Scene::Floodlight.end(&mut site);
        assert_eq!(site.bootstrap()["lights"][0]["isLightOn"], true);
        assert!(site.patch("lights", "nope", &json!({})).is_none());
        assert!(site.patch("users", FLOODLIGHT, &json!({})).is_none());
    }
}
