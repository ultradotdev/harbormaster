//! Publishes UniFi Protect devices as HomeKit accessories and keeps them
//! current from Protect's realtime update stream.
//!
//! Cameras appear as motion sensors (video comes later), doorbells add a
//! doorbell button, door and window sensors add contact state, and so on.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use harbormaster_hap::model::kind;
use harbormaster_hap::{
    Accessory, Bridge, Characteristic, Database, Format, Info, SnapshotReason, SnapshotSource, Store,
};
use bytes::Bytes;
use harbormaster_protect::{Client, FeedOptions, Fingerprint, Segment, Update};
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::recording::{self, Recorder, RecordingIds};
use crate::video::{self, StreamIds, VideoSource};
use harbormaster_hap::recording::{TRIGGER_DOORBELL, TRIGGER_MOTION};
use crate::{config, secrets};

/// Remembers the devices last seen, so the same accessories can be published
/// while the console is unreachable. Without this, HomeKit would see them
/// vanish after a restart and forget their rooms and automations.
const CACHE_FILE: &str = "protect-devices.json";

/// How long the console may say nothing before the connection is presumed
/// dead.
const UPDATE_SILENCE: Duration = Duration::from_secs(90);

/// Reserved instance ids, one block per optional service, so that enabling
/// or disabling a feature in Protect never renumbers the others.
mod iid {
    pub const MOTION: u64 = 100;
    pub const DOORBELL: u64 = 110;
    pub const CONTACT: u64 = 120;
    pub const TEMPERATURE: u64 = 130;
    pub const HUMIDITY: u64 = 140;
    pub const LIGHT_LEVEL: u64 = 150;
    pub const LEAK: u64 = 160;
    pub const BATTERY: u64 = 170;
    /// HomeKit expects a camera to handle two viewers at once.
    pub const STREAMS: [u64; 2] = [200, 210];
    pub const LIGHTBULB: u64 = 180;
    /// Three services, ten ids apart: camera switches, recording, data stream.
    pub const RECORDING: u64 = 300;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Camera,
    Sensor,
    Light,
}

impl Kind {
    /// The name Protect uses for this kind of object in updates.
    fn model_key(self) -> &'static str {
        match self {
            Kind::Camera => "camera",
            Kind::Sensor => "sensor",
            Kind::Light => "light",
        }
    }

    fn section(self) -> &'static str {
        match self {
            Kind::Camera => "cameras",
            Kind::Sensor => "sensors",
            Kind::Light => "lights",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Features {
    pub motion: bool,
    pub doorbell: bool,
    pub contact: bool,
    pub temperature: bool,
    pub humidity: bool,
    pub light_level: bool,
    pub leak: bool,
    pub battery: bool,
}

/// Everything needed to publish one Protect device as an accessory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDef {
    pub kind: Kind,
    pub id: String,
    pub name: String,
    pub model: String,
    pub mac: String,
    pub firmware: String,
    pub features: Features,
    /// Size of the camera's best stream, if it has video to offer.
    #[serde(default)]
    pub video: Option<(u16, u16)>,
}

impl DeviceDef {
    /// Key under which the store keeps this device's stable accessory id.
    fn store_key(&self) -> String {
        format!("protect:{}:{}", self.kind.model_key(), self.id)
    }
}

/// Works out which accessories the console's inventory calls for.
pub fn definitions(bootstrap: &Value) -> Vec<DeviceDef> {
    let mut out = Vec::new();
    for kind in [Kind::Camera, Kind::Sensor, Kind::Light] {
        for device in bootstrap[kind.section()].as_array().into_iter().flatten() {
            let text = |key: &str| device[key].as_str().unwrap_or_default().to_owned();
            let (id, model) = (text("id"), text("type"));
            // Devices still being adopted have no stable identity yet.
            if id.is_empty() || device["isAdopted"] == false {
                continue;
            }
            let enabled = |settings: &str| device[settings]["isEnabled"] == true;
            let mount = device["mountType"].as_str().unwrap_or("none");
            let features = match kind {
                Kind::Camera => Features {
                    motion: true,
                    doorbell: device["featureFlags"]["isDoorbell"] == true,
                    ..Features::default()
                },
                Kind::Light => Features { motion: true, ..Features::default() },
                Kind::Sensor => Features {
                    motion: enabled("motionSettings"),
                    contact: matches!(mount, "door" | "window" | "garage"),
                    leak: mount == "leak",
                    temperature: enabled("temperatureSettings"),
                    humidity: enabled("humiditySettings"),
                    light_level: enabled("lightSettings"),
                    battery: true,
                    doorbell: false,
                },
            };
            let name = [text("name"), text("marketName"), model.clone()]
                .into_iter()
                .find(|n| !n.is_empty())
                .unwrap_or_else(|| "Protect device".to_owned());
            let video = (kind == Kind::Camera)
                .then(|| channels(device).into_iter().map(|c| (c.width, c.height)).max())
                .flatten();
            out.push(DeviceDef {
                kind,
                video,
                id,
                name,
                model: [text("marketName"), model].into_iter().find(|m| !m.is_empty()).unwrap_or_default(),
                mac: text("mac"),
                firmware: text("firmwareVersion"),
                features,
            });
        }
    }
    out
}

/// One of a camera's video streams: the same picture at one quality.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Channel {
    /// The number Protect knows the stream by; 0 is the best quality.
    id: u8,
    width: u16,
    height: u16,
}

/// A camera's usable streams.
fn channels(camera: &Value) -> Vec<Channel> {
    camera["channels"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["enabled"] != false)
        // A doorbell's package camera is a second lens with a different
        // view, so it must never stand in for the main picture.
        .filter(|c| c["name"] != "Package Camera")
        .filter_map(|c| {
            Some(Channel {
                id: u8::try_from(c["id"].as_u64()?).ok()?,
                width: u16::try_from(c["width"].as_u64()?).ok()?,
                height: u16::try_from(c["height"].as_u64()?).ok()?,
            })
        })
        .filter(|c| c.width > 0 && c.height > 0)
        .collect()
}

/// What is known about the console right now, shared with the parts that
/// serve video and snapshots on demand.
#[derive(Default)]
pub struct Live {
    inner: RwLock<LiveInner>,
}

#[derive(Default)]
struct LiveInner {
    /// Present while signed in.
    client: Option<Arc<Client>>,
    channels: HashMap<String, Vec<Channel>>,
    /// Which camera each accessory is.
    cameras: HashMap<u64, String>,
}

impl Live {
    fn update(&self, client: Arc<Client>, bootstrap: &Value) {
        let mut inner = self.inner.write().unwrap();
        inner.client = Some(client);
        inner.channels = bootstrap["cameras"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| Some((c["id"].as_str()?.to_owned(), channels(c))))
            .collect();
    }

    fn disconnected(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.client = None;
        inner.channels.clear();
    }
}

impl SnapshotSource for Live {
    fn snapshot(
        &self,
        aid: u64,
        width: u32,
        height: u32,
        _reason: SnapshotReason,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            let (client, camera) = {
                let inner = self.inner.read().unwrap();
                (inner.client.clone()?, inner.cameras.get(&aid)?.clone())
            };
            match client.snapshot(&camera, width, height).await {
                Ok(jpeg) => Some(jpeg.to_vec()),
                Err(e) => {
                    tracing::warn!("snapshot failed: {e}");
                    None
                }
            }
        })
    }
}

/// Camera stills, withheld when HomeKit's switches for the camera say so.
struct Snapshots {
    live: Arc<Live>,
    recorder: Option<Arc<Recorder>>,
}

impl SnapshotSource for Snapshots {
    fn snapshot(
        &self,
        aid: u64,
        width: u32,
        height: u32,
        reason: SnapshotReason,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            if self.recorder.as_ref().is_some_and(|r| !r.snapshot_allowed(aid, reason)) {
                tracing::debug!("withholding a snapshot of accessory {aid}: switched off in HomeKit");
                return None;
            }
            self.live.snapshot(aid, width, height, reason).await
        })
    }
}

/// Reads one camera's video from the console's native live feed.
struct ProtectVideo {
    live: Arc<Live>,
    camera: String,
}

impl ProtectVideo {
    /// The signed-in client and the stream to read for a picture about
    /// `width` pixels wide: the smallest that is at least that wide, else
    /// the largest.
    fn choose(&self, width: u16) -> Option<(Arc<Client>, u8)> {
        let inner = self.live.inner.read().unwrap();
        let mut available: Vec<&Channel> = inner.channels.get(&self.camera)?.iter().collect();
        available.sort_by_key(|c| c.width);
        let channel = available.iter().find(|c| c.width >= width).or(available.last())?;
        Some((inner.client.clone()?, channel.id))
    }
}

impl VideoSource for ProtectVideo {
    fn available(&self) -> bool {
        self.choose(0).is_some()
    }

    fn open(&self, width: u16) -> Option<mpsc::Receiver<Bytes>> {
        let (client, channel) = self.choose(width)?;
        let camera = self.camera.clone();
        // A little slack so a brief stall in ffmpeg does not stall the
        // connection to the console; fragments are a tenth of a second.
        let (sender, receiver) = mpsc::channel(32);
        tokio::spawn(async move {
            let options = FeedOptions { channel, ..FeedOptions::default() };
            let mut feed = match client.livestream(&camera, options).await {
                Ok(feed) => feed,
                Err(e) => {
                    tracing::warn!("could not open the live feed: {e}");
                    return;
                }
            };
            loop {
                let data = match feed.next().await {
                    Ok(Some(Segment::Init { data, .. } | Segment::Media(data))) => data,
                    Ok(None) => {
                        tracing::info!("the console closed a live feed");
                        return;
                    }
                    Err(e) => {
                        tracing::warn!("live feed stopped: {e}");
                        return;
                    }
                };
                // The receiver goes away when the viewer does, which ends
                // this task and closes the feed.
                if sender.send(data).await.is_err() {
                    return;
                }
            }
        });
        Some(receiver)
    }
}

/// Whether the `devices` filter in the config selects this device.
fn selected(def: &DeviceDef, filter: Option<&[String]>) -> bool {
    filter.is_none_or(|entries| entries.iter().any(|entry| matches_entry(def, entry)))
}

fn matches_entry(def: &DeviceDef, entry: &str) -> bool {
    let entry = entry.trim();
    def.name.eq_ignore_ascii_case(entry) || def.id == entry || def.mac.eq_ignore_ascii_case(&entry.replace(':', ""))
}

/// Instance ids of the characteristics a device's updates feed.
#[derive(Debug, Default)]
struct Handles {
    aid: u64,
    name: String,
    /// One per sensor service, all tracking whether the device is online.
    active: Vec<u64>,
    motion: Option<u64>,
    /// Whether the device currently reports plain motion, and whether it
    /// reports a recognised person, vehicle or the like. Some cameras only
    /// ever report the second, and either one counts as motion in HomeKit.
    plain_motion: AtomicBool,
    smart_motion: AtomicBool,
    ring: Option<u64>,
    contact: Option<u64>,
    temperature: Option<u64>,
    humidity: Option<u64>,
    light_level: Option<u64>,
    leak: Option<u64>,
    battery_level: Option<u64>,
    low_battery: Option<u64>,
    /// One per sensor service, all showing whether the case was opened.
    tampered: Vec<u64>,
    light_on: Option<u64>,
    brightness: Option<u64>,
    streams: Vec<StreamIds>,
    recording: Option<RecordingIds>,
}

fn status_active() -> Characteristic {
    Characteristic::sensor(kind::STATUS_ACTIVE, Format::Bool, json!(false))
}

fn build_accessory(aid: u64, def: &DeviceDef, with_video: bool) -> (Accessory, Handles) {
    let firmware = if def.firmware.is_empty() { "0" } else { &def.firmware };
    let mut accessory = Accessory::new(
        aid,
        &Info {
            name: &def.name,
            manufacturer: "Ubiquiti",
            model: &def.model,
            serial_number: &def.mac,
            firmware_revision: firmware,
        },
    );
    let mut handles = Handles { aid, name: def.name.clone(), ..Handles::default() };
    let f = &def.features;
    // The first service present is the primary one.
    let primary = std::cell::Cell::new(true);
    // Battery sensors can tell when their case has been opened.
    let reports_tampering = def.kind == Kind::Sensor;
    let tampered = std::cell::RefCell::new(Vec::new());
    let sensor = |accessory: &mut Accessory, base: u64, service: &'static str, value: Characteristic| {
        let mut characteristics = vec![value, status_active()];
        if reports_tampering {
            characteristics
                .push(Characteristic::sensor(kind::STATUS_TAMPERED, Format::Uint8, json!(0)).range(0.0, 1.0, 1.0));
        }
        let ids = accessory.add_service_at(base, service, primary.take(), characteristics);
        tampered.borrow_mut().extend(ids.get(2));
        (ids[0], ids[1])
    };

    if f.doorbell {
        // Stateless: reads return null and each press is sent as an event.
        let press = Characteristic::sensor(kind::PROGRAMMABLE_SWITCH_EVENT, Format::Uint8, Value::Null)
            .range(0.0, 0.0, 1.0);
        let ids = accessory.add_service_at(iid::DOORBELL, kind::DOORBELL, primary.take(), vec![press]);
        handles.ring = Some(ids[0]);
    }
    if f.contact {
        let state = Characteristic::sensor(kind::CONTACT_SENSOR_STATE, Format::Uint8, json!(0)).range(0.0, 1.0, 1.0);
        let (value, active) = sensor(&mut accessory, iid::CONTACT, kind::CONTACT_SENSOR, state);
        (handles.contact, _) = (Some(value), handles.active.push(active));
    }
    if f.motion {
        let state = Characteristic::sensor(kind::MOTION_DETECTED, Format::Bool, json!(false));
        let (value, active) = sensor(&mut accessory, iid::MOTION, kind::MOTION_SENSOR, state);
        (handles.motion, _) = (Some(value), handles.active.push(active));
    }
    if f.leak {
        let state = Characteristic::sensor(kind::LEAK_DETECTED, Format::Uint8, json!(0)).range(0.0, 1.0, 1.0);
        let (value, active) = sensor(&mut accessory, iid::LEAK, kind::LEAK_SENSOR, state);
        (handles.leak, _) = (Some(value), handles.active.push(active));
    }
    if f.temperature {
        let state = Characteristic::sensor(kind::CURRENT_TEMPERATURE, Format::Float, json!(0.0))
            .unit("celsius")
            .range(-100.0, 100.0, 0.1);
        let (value, active) = sensor(&mut accessory, iid::TEMPERATURE, kind::TEMPERATURE_SENSOR, state);
        (handles.temperature, _) = (Some(value), handles.active.push(active));
    }
    if f.humidity {
        let state = Characteristic::sensor(kind::CURRENT_RELATIVE_HUMIDITY, Format::Float, json!(0.0))
            .unit("percentage")
            .range(0.0, 100.0, 1.0);
        let (value, active) = sensor(&mut accessory, iid::HUMIDITY, kind::HUMIDITY_SENSOR, state);
        (handles.humidity, _) = (Some(value), handles.active.push(active));
    }
    if f.light_level {
        let state = Characteristic::sensor(kind::CURRENT_AMBIENT_LIGHT_LEVEL, Format::Float, json!(0.0001))
            .unit("lux")
            .range(0.0001, 100_000.0, 0.0001);
        let (value, active) = sensor(&mut accessory, iid::LIGHT_LEVEL, kind::LIGHT_SENSOR, state);
        (handles.light_level, _) = (Some(value), handles.active.push(active));
    }
    if def.kind == Kind::Light {
        let ids = accessory.add_service_at(
            iid::LIGHTBULB,
            kind::LIGHTBULB,
            false,
            vec![
                Characteristic { writable: true, ..Characteristic::sensor(kind::ON, Format::Bool, json!(false)) },
                Characteristic { writable: true, ..Characteristic::sensor(kind::BRIGHTNESS, Format::Int, json!(100)) }
                    .unit("percentage")
                    .range(0.0, 100.0, 1.0),
            ],
        );
        (handles.light_on, handles.brightness) = (Some(ids[0]), Some(ids[1]));
    }
    if let (true, Some((width, height))) = (with_video, def.video) {
        let offered = video::resolutions(width, height);
        handles.streams = iid::STREAMS.iter().map(|iid| video::add_stream_service(&mut accessory, *iid, &offered)).collect();
        let triggers = TRIGGER_MOTION | if f.doorbell { TRIGGER_DOORBELL } else { 0 };
        let motion_service = handles.motion.is_some().then_some(iid::MOTION);
        handles.recording =
            Some(recording::add_services(&mut accessory, iid::RECORDING, &offered, triggers, motion_service));
    }
    if f.battery {
        let ids = accessory.add_service_at(
            iid::BATTERY,
            kind::BATTERY,
            false,
            vec![
                Characteristic::sensor(kind::BATTERY_LEVEL, Format::Uint8, json!(100))
                    .unit("percentage")
                    .range(0.0, 100.0, 1.0),
                // 2 means "not chargeable".
                Characteristic::constant(kind::CHARGING_STATE, Format::Uint8, json!(2)).range(0.0, 2.0, 1.0),
                Characteristic::sensor(kind::STATUS_LOW_BATTERY, Format::Uint8, json!(0)).range(0.0, 1.0, 1.0),
            ],
        );
        (handles.battery_level, handles.low_battery) = (Some(ids[0]), Some(ids[2]));
    }
    handles.tampered = tampered.into_inner();
    (accessory, handles)
}

/// The floodlight has six brightness steps; HomeKit works in percent.
fn level_to_percent(level: u64) -> u64 {
    (level.clamp(1, 6) * 100 + 3) / 6
}

fn percent_to_level(percent: u64) -> u64 {
    ((percent.min(100) * 6 + 50) / 100).clamp(1, 6)
}

/// Lets HomeKit switch a floodlight on and off and set its brightness. The
/// change shows in HomeKit at once and is undone if the console refuses it.
fn install_light_control(db: &Arc<Database>, live: &Arc<Live>, aid: u64, handles: &Handles, id: &str) {
    let control = |iid: u64, changes: fn(&Value) -> Option<Value>| {
        let (db_for_task, live, id, name) = (db.clone(), live.clone(), id.to_owned(), handles.name.clone());
        db.on_write(
            aid,
            iid,
            Arc::new(move |value, _| {
                let changes = changes(value).ok_or(harbormaster_hap::model::status::INVALID_VALUE)?;
                let previous = db_for_task.read(aid, iid).ok();
                let (db, live, id, name) = (db_for_task.clone(), live.clone(), id.clone(), name.clone());
                tokio::spawn(async move {
                    let client = live.inner.read().unwrap().client.clone();
                    let result = match client {
                        Some(client) => client.update_device("lights", &id, &changes).await.map_err(|e| e.to_string()),
                        None => Err("the console is not reachable".to_owned()),
                    };
                    if let Err(why) = result {
                        tracing::warn!("{name}: could not change the light: {why}");
                        if let Some(previous) = previous {
                            db.set(aid, iid, previous);
                        }
                    }
                });
                Ok(None)
            }),
        );
    };
    if let Some(iid) = handles.light_on {
        control(iid, |v| Some(json!({ "lightOnSettings": { "isLedForceOn": v.as_bool()? } })));
    }
    if let Some(iid) = handles.brightness {
        control(iid, |v| Some(json!({ "lightDeviceSettings": { "ledLevel": percent_to_level(v.as_u64()?) } })));
    }
}

/// The Protect devices currently published, and how updates reach them.
#[derive(Default)]
pub struct Devices {
    defs: Vec<DeviceDef>,
    handles: HashMap<(&'static str, String), Handles>,
    /// Set when live video can be served: the shared console state and the
    /// ffmpeg to run.
    video: Option<(Arc<Live>, PathBuf)>,
    /// The console connection that commands are sent over.
    live: Option<Arc<Live>>,
    /// Set when recordings can be made for HomeKit.
    recorder: Option<Arc<Recorder>>,
}

impl Devices {
    /// Publishes devices that are new, and rebuilds any whose definition
    /// changed (a feature switched on in Protect, say). Returns how many
    /// accessories were added or rebuilt.
    fn add(&mut self, defs: &[DeviceDef], store: &Store, db: &Arc<Database>) -> Result<usize> {
        let mut changed = 0;
        for def in defs {
            let key = (def.kind.model_key(), def.id.clone());
            let existing = self.defs.iter().position(|d| d.kind == def.kind && d.id == def.id);
            if existing.is_some_and(|i| self.defs[i] == *def) {
                continue;
            }
            let aid = store.accessory_id(&def.store_key())?;
            let (accessory, handles) = build_accessory(aid, def, self.video.is_some());
            db.replace(accessory);
            crate::status::global().device_kind(aid, def.kind.model_key());
            if let Some(live) = &self.live {
                install_light_control(db, live, aid, &handles, &def.id);
            }
            if let Some((live, ffmpeg)) = &self.video {
                for ids in &handles.streams {
                    let source = Arc::new(ProtectVideo { live: live.clone(), camera: def.id.clone() });
                    let gate = self.recorder.clone().map(|recorder| -> video::Gate {
                        Arc::new(move || recorder.live_view_refusal(aid))
                    });
                    video::install(db, aid, *ids, &def.name, source, ffmpeg, gate);
                }
                if let (Some(ids), Some(recorder)) = (handles.recording, &self.recorder) {
                    let source = Arc::new(ProtectVideo { live: live.clone(), camera: def.id.clone() });
                    let switches: Vec<u64> = handles.streams.iter().map(StreamIds::active).collect();
                    recorder.install(db, aid, ids, &def.name, &def.id, source, &switches);
                }
                if def.kind == Kind::Camera {
                    live.inner.write().unwrap().cameras.insert(aid, def.id.clone());
                }
            }
            self.handles.insert(key, handles);
            match existing {
                Some(i) => self.defs[i] = def.clone(),
                None => self.defs.push(def.clone()),
            }
            changed += 1;
        }
        Ok(changed)
    }

    /// Applies changed fields of one device. `live` is false when replaying
    /// a snapshot, where a past ring must not sound the doorbell again.
    fn apply(&self, db: &Database, model_key: &str, id: &str, data: &Value, live: bool) {
        let Some((_, h)) = self.handles.iter().find(|((k, i), _)| *k == model_key && i == id) else {
            return;
        };
        let set = |iid: Option<u64>, value: Value| {
            if let Some(iid) = iid {
                db.set(h.aid, iid, value);
            }
        };
        if let Some(state) = data["state"].as_str() {
            let online = state == "CONNECTED";
            for iid in &h.active {
                if db.set(h.aid, *iid, json!(online)) && live {
                    tracing::info!("{} is {}", h.name, if online { "online" } else { "offline" });
                }
            }
        }
        let motion = if model_key == "light" { "isPirMotionDetected" } else { "isMotionDetected" };
        if let Some(detected) = data[motion].as_bool() {
            h.plain_motion.store(detected, Ordering::Relaxed);
        }
        if let Some(detected) = data["isSmartDetected"].as_bool() {
            h.smart_motion.store(detected, Ordering::Relaxed);
        }
        if let (true, Some(iid)) = (data[motion].is_boolean() || data["isSmartDetected"].is_boolean(), h.motion) {
            let detected = h.plain_motion.load(Ordering::Relaxed) || h.smart_motion.load(Ordering::Relaxed);
            // The console repeats the current state in later updates; only
            // a real change is an event.
            let changed = db.read(h.aid, iid).ok() != Some(json!(detected));
            if db.set(h.aid, iid, json!(detected)) && live && changed {
                tracing::info!("{}: motion {}", h.name, if detected { "detected" } else { "ended" });
                if let (true, Some(recorder)) = (detected, &self.recorder) {
                    recorder.event_started(h.aid);
                }
            }
        }
        if let (true, Some(iid), true) = (live, h.ring, data["lastRing"].is_number()) {
            tracing::info!("doorbell ring: {}", h.name);
            if let Some(recorder) = &self.recorder {
                recorder.event_started(h.aid);
            }
            // 0 is a single press, the only kind a doorbell has.
            db.emit(h.aid, iid, json!(0));
        }
        if let Some(on) = data["isLightOn"].as_bool() {
            set(h.light_on, json!(on));
        }
        if let Some(level) = data["lightDeviceSettings"]["ledLevel"].as_u64() {
            set(h.brightness, json!(level_to_percent(level)));
        }
        // A time while the case is open, null once it is closed again.
        if let Some(opened) = data.get("tamperingDetectedAt") {
            for iid in &h.tampered {
                db.set(h.aid, *iid, json!(u8::from(!opened.is_null())));
            }
        }
        if let Some(open) = data["isOpened"].as_bool() {
            // HomeKit: 0 is contact detected (closed), 1 is not detected (open).
            set(h.contact, json!(u8::from(open)));
        }
        // Protect records when a leak was last seen; null means dry.
        if let Some(leak) = data.get("leakDetectedAt") {
            set(h.leak, json!(u8::from(!leak.is_null())));
        }
        let stat = |name: &str| data["stats"][name]["value"].as_f64();
        if let Some(celsius) = stat("temperature") {
            set(h.temperature, json!(celsius.clamp(-100.0, 100.0)));
        }
        if let Some(percent) = stat("humidity") {
            set(h.humidity, json!(percent.clamp(0.0, 100.0)));
        }
        if let Some(lux) = stat("light") {
            set(h.light_level, json!(lux.clamp(0.0001, 100_000.0)));
        }
        if let Some(percent) = data["batteryStatus"]["percentage"].as_f64() {
            set(h.battery_level, json!(percent.clamp(0.0, 100.0).round() as u8));
        }
        if let Some(low) = data["batteryStatus"]["isLow"].as_bool() {
            set(h.low_battery, json!(u8::from(low)));
        }
    }

    /// Brings every device up to date from a full inventory.
    fn apply_snapshot(&self, db: &Database, bootstrap: &Value) {
        for kind in [Kind::Camera, Kind::Sensor, Kind::Light] {
            for device in bootstrap[kind.section()].as_array().into_iter().flatten() {
                if let Some(id) = device["id"].as_str() {
                    self.apply(db, kind.model_key(), id, device, false);
                }
            }
        }
    }

    fn apply_update(&self, db: &Database, update: &Update) {
        crate::status::global().console_update();
        if update.action == "update" {
            self.apply(db, &update.model_key, &update.id, &update.data, true);
        }
    }

    /// Marks everything offline, for when the console cannot be reached.
    fn mark_offline(&self, db: &Database) {
        for h in self.handles.values() {
            for iid in &h.active {
                db.set(h.aid, *iid, json!(false));
            }
        }
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }
}

fn cache_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CACHE_FILE)
}

fn load_cache(state_dir: &Path) -> Vec<DeviceDef> {
    let path = cache_path(state_dir);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!("ignoring unreadable {}: {e}", path.display());
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

fn save_cache(state_dir: &Path, defs: &[DeviceDef]) {
    let path = cache_path(state_dir);
    let tmp = path.with_extension("tmp");
    let result = serde_json::to_vec_pretty(defs)
        .map_err(std::io::Error::other)
        .and_then(|json| std::fs::write(&tmp, json))
        .and_then(|()| std::fs::rename(&tmp, &path));
    if let Err(e) = result {
        tracing::warn!("could not save {}: {e}", path.display());
    }
}

pub struct ProtectBridge {
    live: Arc<Live>,
    state_dir: PathBuf,
    config: config::Protect,
    pin: Fingerprint,
    store: Arc<Store>,
    db: Arc<Database>,
    devices: Devices,
}

impl ProtectBridge {
    /// Publishes the devices known from the last run, so HomeKit sees a
    /// stable set of accessories before the console has even been contacted.
    pub fn prepare(
        state_dir: &Path,
        config: config::Protect,
        store: Arc<Store>,
        db: Arc<Database>,
    ) -> Result<Self> {
        let pin = config
            .fingerprint
            .as_deref()
            .context("[protect] has no fingerprint yet; run `harbormaster protect-check` first")?
            .parse()
            .context("fingerprint in config.toml")?;
        let live = Arc::new(Live::default());
        let ffmpeg = video::find_ffmpeg();
        if ffmpeg.is_none() {
            tracing::warn!("ffmpeg is not installed, so cameras will have no video");
        }
        let recorder = ffmpeg.as_deref().map(|path| Recorder::new(state_dir, path));
        let mut devices =
            Devices { video: ffmpeg.map(|path| (live.clone(), path)), live: Some(live.clone()), recorder, ..Devices::default() };
        let mut cached = load_cache(state_dir);
        cached.retain(|def| selected(def, config.devices.as_deref()));
        devices.add(&cached, &store, &db)?;
        if !cached.is_empty() {
            tracing::info!("publishing {} UniFi Protect devices from the last run", cached.len());
        }
        Ok(Self { live, state_dir: state_dir.to_owned(), config, pin, store, db, devices })
    }

    /// Where the HomeKit server gets camera snapshots.
    pub fn snapshots(&self) -> Arc<dyn SnapshotSource> {
        Arc::new(Snapshots { live: self.live.clone(), recorder: self.devices.recorder.clone() })
    }

    /// Stays connected to the console forever, reconnecting as needed.
    pub async fn run(mut self, bridge: Arc<Bridge>) {
        let mut delay = Duration::from_secs(1);
        loop {
            let started = std::time::Instant::now();
            match self.session(&bridge).await {
                Ok(()) => tracing::warn!("UniFi Protect closed the update stream; reconnecting"),
                Err(e) => tracing::warn!("UniFi Protect connection lost: {e:#}"),
            }
            self.devices.mark_offline(&self.db);
            self.live.disconnected();
            crate::status::global().console_disconnected();
            // A session that lasted a while was healthy, so start over quickly.
            if started.elapsed() > Duration::from_secs(60) {
                delay = Duration::from_secs(1);
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(60));
        }
    }

    /// One sign-in, inventory read and update stream, until it ends.
    async fn session(&mut self, bridge: &Bridge) -> Result<()> {
        let password = secrets::protect_password(&self.state_dir, &self.config.username)?;
        let mut client = Client::new(&self.config.host, self.config.port, self.pin);
        client.login(&self.config.username, &password).await?;
        drop(password);
        let client = Arc::new(client);

        let bootstrap = client.bootstrap_raw().await?;
        self.live.update(client.clone(), &bootstrap);
        let all = definitions(&bootstrap);
        let filter = self.config.devices.as_deref();
        for entry in filter.into_iter().flatten() {
            if !all.iter().any(|def| matches_entry(def, entry)) {
                tracing::warn!("no UniFi Protect device matches \"{entry}\" in the devices filter");
            }
        }
        let defs: Vec<DeviceDef> = all.into_iter().filter(|def| selected(def, filter)).collect();
        let added = self.devices.add(&defs, &self.store, &self.db)?;
        if added > 0 {
            save_cache(&self.state_dir, &self.devices.defs);
            tracing::info!("added or updated {added} UniFi Protect devices");
            bridge.config_changed();
        }
        self.devices.apply_snapshot(&self.db, &bootstrap);
        crate::status::global().console_update();
        tracing::info!(
            "connected to UniFi Protect at {} ({} devices)",
            self.config.host,
            self.devices.len()
        );

        let mut updates = client.updates(bootstrap["lastUpdateId"].as_str()).await?;
        // A busy site sends several updates a second and even a quiet one
        // sends statistics every few seconds, so a long silence means the
        // connection has died without saying so. Reconnect rather than sit
        // deaf to motion and doorbell presses.
        loop {
            match tokio::time::timeout(UPDATE_SILENCE, updates.next()).await {
                Ok(update) => match update? {
                    Some(update) => self.devices.apply_update(&self.db, &update),
                    None => return Ok(()),
                },
                Err(_) => anyhow::bail!("no updates for {} seconds", UPDATE_SILENCE.as_secs()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap() -> Value {
        json!({
            "cameras": [
                {"id": "cam1", "mac": "AA01", "name": "Front Door", "type": "UVC G4 Doorbell Pro",
                 "marketName": "G4 Doorbell Pro", "firmwareVersion": "4.1.2", "state": "CONNECTED",
                 "isMotionDetected": false, "lastRing": 1000, "featureFlags": {"isDoorbell": true}},
                {"id": "cam2", "mac": "AA02", "name": "Garage", "type": "UVC G5 Flex", "state": "DISCONNECTED",
                 "isMotionDetected": false, "featureFlags": {"isDoorbell": false}},
                {"id": "cam3", "mac": "AA03", "name": "Adopting", "type": "UVC G5 Flex", "isAdopted": false}
            ],
            "sensors": [
                {"id": "sen1", "mac": "BB01", "name": "Front Door Sensor", "type": "USL-Entry-US",
                 "state": "CONNECTED", "mountType": "door", "isOpened": false,
                 "batteryStatus": {"percentage": 96, "isLow": false},
                 "motionSettings": {"isEnabled": false}, "temperatureSettings": {"isEnabled": false}},
                {"id": "sen2", "mac": "BB02", "name": "Yard", "type": "USL-Environmental-US", "state": "CONNECTED",
                 "mountType": "none", "batteryStatus": {"percentage": 93, "isLow": false},
                 "stats": {"temperature": {"value": 17.17}, "humidity": {"value": 80}, "light": {"value": 801}},
                 "temperatureSettings": {"isEnabled": true}, "humiditySettings": {"isEnabled": true},
                 "lightSettings": {"isEnabled": true}, "motionSettings": {"isEnabled": false}}
            ],
            "lights": [
                {"id": "lit1", "mac": "CC01", "name": "Floodlight", "type": "UP FloodLight", "state": "CONNECTED",
                 "isPirMotionDetected": false}
            ],
            "lastUpdateId": "u1"
        })
    }

    struct Fixture {
        dir: PathBuf,
        store: Arc<Store>,
        db: Arc<Database>,
        devices: Devices,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("hm-protect-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let store = Arc::new(Store::open(dir.join("state.json")).unwrap());
            let db = Database::new();
            let mut devices = Devices::default();
            devices.add(&definitions(&bootstrap()), &store, &db).unwrap();
            devices.apply_snapshot(&db, &bootstrap());
            Self { dir, store, db, devices }
        }

        fn aid(&self, kind: &'static str, id: &str) -> u64 {
            self.devices.handles[&(kind, id.to_owned())].aid
        }

        fn update(&self, model_key: &str, id: &str, data: Value) {
            let update = Update {
                action: "update".into(),
                model_key: model_key.into(),
                id: id.into(),
                new_update_id: None,
                data,
            };
            self.devices.apply_update(&self.db, &update);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn inventory_becomes_the_right_accessories() {
        let defs = definitions(&bootstrap());
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["Front Door", "Garage", "Front Door Sensor", "Yard", "Floodlight"]);
        assert!(defs[0].features.doorbell && defs[0].features.motion);
        assert_eq!(defs[0].model, "G4 Doorbell Pro");
        assert_eq!(
            defs[2].features,
            Features { contact: true, battery: true, ..Features::default() }
        );
        assert_eq!(
            defs[3].features,
            Features { temperature: true, humidity: true, light_level: true, battery: true, ..Features::default() }
        );
    }

    fn doorbell_with_channels() -> Value {
        json!({
            "cameras": [{
                "id": "cam1", "mac": "AA01", "name": "Front Door", "type": "UVC G4 Doorbell Pro", "state": "CONNECTED",
                "featureFlags": {"isDoorbell": true},
                "channels": [
                    {"id": 0, "name": "High", "enabled": true, "width": 1600, "height": 1200},
                    {"id": 1, "name": "Medium", "enabled": true, "width": 960, "height": 720},
                    {"id": 2, "name": "Low", "enabled": false, "width": 480, "height": 360},
                    {"id": 3, "name": "Package Camera", "enabled": true, "width": 1600, "height": 1200}
                ]
            }]
        })
    }

    #[test]
    fn camera_video_picks_a_fitting_stream_and_never_the_package_camera() {
        let bootstrap = doorbell_with_channels();
        let defs = definitions(&bootstrap);
        assert_eq!(defs[0].video, Some((1600, 1200)));
        // A camera that lists no streams offers no video.
        assert_eq!(definitions(&super::tests::bootstrap())[0].video, None);

        let live = Arc::new(Live::default());
        let source = ProtectVideo { live: live.clone(), camera: "cam1".into() };
        assert!(!source.available(), "nothing is available before the console is reached");

        let pin: Fingerprint = "00".repeat(32).parse().unwrap();
        live.update(Arc::new(Client::new("10.0.0.5", 443, pin)), &bootstrap);
        assert!(source.available());
        let channel = |width| source.choose(width).unwrap().1;
        assert_eq!(channel(640), 1);
        assert_eq!(channel(960), 1);
        assert_eq!(channel(1280), 0);
        assert_eq!(channel(1920), 0, "falls back to the largest");
        // Never the switched-off stream (2) or the package camera (3).
        assert!((0..=2000).step_by(40).all(|width| channel(width) < 2));

        live.disconnected();
        assert!(!source.available());
    }

    #[tokio::test]
    async fn changed_definition_rebuilds_the_accessory_with_video() {
        let dir = std::env::temp_dir().join(format!("hm-protect-{}-video", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::open(dir.join("state.json")).unwrap());
        let db = Database::new();
        let live = Arc::new(Live::default());
        let mut devices =
            Devices { video: Some((live.clone(), PathBuf::from("/nonexistent/ffmpeg"))), ..Devices::default() };

        // From the cache of an older run: the camera is known, but not its video.
        let mut cached = definitions(&doorbell_with_channels());
        cached[0].video = None;
        assert_eq!(devices.add(&cached, &store, &db).unwrap(), 1);
        let aid = devices.handles[&("camera", "cam1".to_owned())].aid;
        let before = db.layout();
        assert_eq!(db.read(aid, iid::STREAMS[0] + 3), Err(harbormaster_hap::model::status::NOT_FOUND));

        // The console is reached and reports the camera's streams.
        assert_eq!(devices.add(&definitions(&doorbell_with_channels()), &store, &db).unwrap(), 1);
        assert_eq!(devices.handles[&("camera", "cam1".to_owned())].aid, aid, "same accessory id");
        assert_ne!(db.layout(), before, "controllers must be told the accessory changed");
        assert_eq!(devices.handles[&("camera", "cam1".to_owned())].streams.len(), 2);
        assert!(db.read(aid, iid::STREAMS[0] + 3).is_ok() && db.read(aid, iid::STREAMS[1] + 3).is_ok());
        assert_eq!(live.inner.read().unwrap().cameras.get(&aid).map(String::as_str), Some("cam1"));
        // Unchanged definitions are left alone.
        assert_eq!(devices.add(&definitions(&doorbell_with_channels()), &store, &db).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn filter_selects_by_name_id_or_mac() {
        let defs = definitions(&bootstrap());
        let pick = |entries: &[&str]| -> Vec<String> {
            let filter: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
            defs.iter().filter(|d| selected(d, Some(&filter))).map(|d| d.name.clone()).collect()
        };
        assert_eq!(pick(&["front door"]), ["Front Door"]);
        assert_eq!(pick(&["cam2", "bb:01"]), ["Garage", "Front Door Sensor"]);
        assert!(pick(&["Front"]).is_empty(), "partial names do not match");
        assert!(pick(&[]).is_empty(), "an empty list publishes nothing");
        assert_eq!(defs.iter().filter(|d| selected(d, None)).count(), 5, "no filter publishes everything");
    }

    #[test]
    fn snapshot_sets_initial_values_without_ringing() {
        let f = Fixture::new("snapshot");
        let mut changes = f.db.subscribe_changes();
        f.devices.apply_snapshot(&f.db, &bootstrap());
        assert!(changes.try_recv().is_err(), "an unchanged snapshot sends no events, and no ring");

        let yard = f.aid("sensor", "sen2");
        assert_eq!(f.db.read(yard, iid::TEMPERATURE + 1), Ok(json!(17.17)));
        assert_eq!(f.db.read(yard, iid::HUMIDITY + 1), Ok(json!(80.0)));
        assert_eq!(f.db.read(yard, iid::LIGHT_LEVEL + 1), Ok(json!(801.0)));
        assert_eq!(f.db.read(yard, iid::BATTERY + 1), Ok(json!(93)));
        // Online and offline cameras are told apart.
        assert_eq!(f.db.read(f.aid("camera", "cam1"), iid::MOTION + 2), Ok(json!(true)));
        assert_eq!(f.db.read(f.aid("camera", "cam2"), iid::MOTION + 2), Ok(json!(false)));
    }

    #[test]
    fn live_updates_drive_motion_contact_and_doorbell() {
        let f = Fixture::new("live");
        let (door, sensor, light) = (f.aid("camera", "cam1"), f.aid("sensor", "sen1"), f.aid("light", "lit1"));
        let mut changes = f.db.subscribe_changes();

        f.update("camera", "cam1", json!({"isMotionDetected": true, "lastMotionDetectionTypes": ["motion"]}));
        assert_eq!(f.db.read(door, iid::MOTION + 1), Ok(json!(true)));
        f.update("camera", "cam1", json!({"isMotionDetected": false}));
        assert_eq!(f.db.read(door, iid::MOTION + 1), Ok(json!(false)));

        f.update("sensor", "sen1", json!({"isOpened": true, "openStatusChangedAt": 5}));
        assert_eq!(f.db.read(sensor, iid::CONTACT + 1), Ok(json!(1)));
        f.update("light", "lit1", json!({"isPirMotionDetected": true}));
        assert_eq!(f.db.read(light, iid::MOTION + 1), Ok(json!(true)));
        while changes.try_recv().is_ok() {}

        // Two rings in a row must produce two events even though nothing "changed".
        f.update("camera", "cam1", json!({"lastRing": 2000, "isSmartDetected": true}));
        f.update("camera", "cam1", json!({"lastRing": 3000}));
        let all: Vec<_> = std::iter::from_fn(|| changes.try_recv().ok()).collect();
        // A recognised person counts as motion even with no plain motion
        // report, which is all some doorbells ever send.
        assert_eq!(all.iter().filter(|c| c.iid == iid::MOTION + 1).map(|c| c.value.clone()).collect::<Vec<_>>(), [json!(true)]);
        f.update("camera", "cam1", json!({"isMotionDetected": true}));
        f.update("camera", "cam1", json!({"isSmartDetected": false}));
        assert_eq!(f.db.read(door, iid::MOTION + 1), Ok(json!(true)), "plain motion is still in progress");
        f.update("camera", "cam1", json!({"isMotionDetected": false}));
        assert_eq!(f.db.read(door, iid::MOTION + 1), Ok(json!(false)));
        while changes.try_recv().is_ok() {}
        let rings: Vec<_> = all.into_iter().filter(|c| c.iid != iid::MOTION + 1).collect();
        assert_eq!(rings.len(), 2);
        assert!(rings.iter().all(|c| c.aid == door && c.iid == iid::DOORBELL + 1 && c.value == json!(0)));
        // The press itself is never stored.
        assert_eq!(f.db.read(door, iid::DOORBELL + 1), Ok(Value::Null));

        // Updates for unknown devices and other object kinds are ignored.
        f.update("camera", "nope", json!({"isMotionDetected": true}));
        f.update("event", "cam1", json!({"isMotionDetected": true}));
        assert!(changes.try_recv().is_err());
    }

    #[test]
    fn floodlight_state_and_sensor_tampering_follow_the_console() {
        let f = Fixture::new("light");
        let light = f.aid("light", "lit1");
        assert_eq!(f.db.read(light, iid::LIGHTBULB + 1), Ok(json!(false)));
        f.update("light", "lit1", json!({"isLightOn": true, "lightDeviceSettings": {"ledLevel": 3}}));
        assert_eq!(f.db.read(light, iid::LIGHTBULB + 1), Ok(json!(true)));
        assert_eq!(f.db.read(light, iid::LIGHTBULB + 2), Ok(json!(50)));
        // Cameras have no light to control.
        let camera = f.aid("camera", "cam1");
        assert_eq!(f.db.read(camera, iid::LIGHTBULB + 1), Err(harbormaster_hap::model::status::NOT_FOUND));

        // Six steps map onto percentages and back without drifting.
        assert_eq!((1..=6).map(level_to_percent).collect::<Vec<_>>(), [17, 33, 50, 67, 83, 100]);
        assert!((1..=6).all(|level| percent_to_level(level_to_percent(level)) == level));
        assert_eq!((percent_to_level(0), percent_to_level(100), percent_to_level(250)), (1, 6, 6));

        let sensor = f.aid("sensor", "sen1");
        assert_eq!(f.db.read(sensor, iid::CONTACT + 3), Ok(json!(0)));
        f.update("sensor", "sen1", json!({"tamperingDetectedAt": 1700000000000u64}));
        assert_eq!(f.db.read(sensor, iid::CONTACT + 3), Ok(json!(1)));
        assert_eq!(f.db.read(sensor, iid::BATTERY + 1), Ok(json!(96)), "other readings are untouched");
        f.update("sensor", "sen1", json!({"tamperingDetectedAt": null}));
        assert_eq!(f.db.read(sensor, iid::CONTACT + 3), Ok(json!(0)));
    }

    #[tokio::test]
    async fn a_light_change_the_console_cannot_take_is_undone() {
        let dir = std::env::temp_dir().join(format!("hm-protect-{}-control", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::open(dir.join("state.json")).unwrap());
        let db = Database::new();
        // Never signed in, so there is no console to send the command to.
        let mut devices = Devices { live: Some(Arc::new(Live::default())), ..Devices::default() };
        devices.add(&definitions(&bootstrap()), &store, &db).unwrap();
        let light = devices.handles[&("light", "lit1".to_owned())].aid;
        let context = harbormaster_hap::model::WriteContext {
            connection: 1,
            local_ip: "127.0.0.1".parse().unwrap(),
            peer_ip: "127.0.0.1".parse().unwrap(),
            shared_secret: None,
        };
        assert_eq!(db.write(light, iid::LIGHTBULB + 1, &json!(true), &context), Ok(json!(true)));
        let mut waited = 0;
        while db.read(light, iid::LIGHTBULB + 1) != Ok(json!(false)) {
            tokio::time::sleep(Duration::from_millis(20)).await;
            waited += 1;
            assert!(waited < 100, "the light still shows on although the command failed");
        }
        assert_eq!(db.write(light, iid::LIGHTBULB + 2, &json!(250), &context), Err(harbormaster_hap::model::status::INVALID_VALUE));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accessory_ids_and_cache_survive_a_restart() {
        let f = Fixture::new("restart");
        let before = f.aid("sensor", "sen2");
        save_cache(&f.dir, &f.devices.defs);

        // A new run with the console unreachable: only the cache is available.
        let db = Database::new();
        let mut devices = Devices::default();
        let cached = load_cache(&f.dir);
        assert_eq!(cached, f.devices.defs);
        assert_eq!(devices.add(&cached, &f.store, &db).unwrap(), 5);
        assert_eq!(devices.handles[&("sensor", "sen2".to_owned())].aid, before);
        // Adding the same devices again is a no-op.
        assert_eq!(devices.add(&cached, &f.store, &db).unwrap(), 0);

        devices.apply_snapshot(&db, &bootstrap());
        devices.mark_offline(&db);
        assert_eq!(db.read(before, iid::TEMPERATURE + 2), Ok(json!(false)));
    }

    /// Replays a real capture when one is available; see `protect-capture`.
    #[test]
    fn replays_a_real_capture_if_present() {
        let Some(dir) = std::env::var_os("HARBORMASTER_CAPTURE_DIR").map(PathBuf::from) else { return };
        let bootstrap: Value = serde_json::from_slice(&std::fs::read(dir.join("bootstrap.json")).unwrap()).unwrap();
        let state = std::env::temp_dir().join(format!("hm-protect-{}-replay", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        let store = Arc::new(Store::open(state.join("state.json")).unwrap());
        let db = Database::new();
        let mut devices = Devices::default();
        let defs = definitions(&bootstrap);
        devices.add(&defs, &store, &db).unwrap();
        devices.apply_snapshot(&db, &bootstrap);

        let mut changes = db.subscribe_changes();
        let (mut motion, mut rings, mut contact) = (0, 0, 0);
        for line in std::fs::read_to_string(dir.join("updates.jsonl")).unwrap().lines() {
            let u: Value = serde_json::from_str(line).unwrap();
            let update = Update {
                action: u["action"].as_str().unwrap().into(),
                model_key: u["modelKey"].as_str().unwrap().into(),
                id: u["id"].as_str().unwrap().into(),
                new_update_id: None,
                data: u["data"].clone(),
            };
            devices.apply_update(&db, &update);
            while let Ok(change) = changes.try_recv() {
                match change.iid {
                    i if i == iid::MOTION + 1 => motion += 1,
                    i if i == iid::DOORBELL + 1 => rings += 1,
                    i if i == iid::CONTACT + 1 => contact += 1,
                    _ => {}
                }
            }
        }
        println!("devices={} motion changes={motion} rings={rings} contact changes={contact}", defs.len());
        for def in &defs {
            println!("  {:?} {:<32} {:?}", def.kind, def.name, def.features);
        }
        let _ = std::fs::remove_dir_all(&state);
        assert!(defs.len() > 1);
    }
}
