//! Publishes UniFi Protect devices as HomeKit accessories and keeps them
//! current from Protect's realtime update stream.
//!
//! Cameras appear as motion sensors (video comes later), doorbells add a
//! doorbell button, door and window sensors add contact state, and so on.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use harbormaster_hap::model::kind;
use harbormaster_hap::{Accessory, Bridge, Characteristic, Database, Format, Info, SnapshotSource, Store};
use harbormaster_protect::{Client, Fingerprint, Update};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::video::{self, StreamIds, VideoSource};
use crate::{config, secrets};

/// Remembers the devices last seen, so the same accessories can be published
/// while the console is unreachable. Without this, HomeKit would see them
/// vanish after a restart and forget their rooms and automations.
const CACHE_FILE: &str = "protect-devices.json";

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

/// One of a camera's video streams, as Protect serves it over RTSP.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Channel {
    width: u16,
    height: u16,
    /// The secret path component of the stream's address.
    alias: String,
}

/// A camera's usable streams. Only channels with RTSP switched on in
/// Protect can be read.
fn channels(camera: &Value) -> Vec<Channel> {
    camera["channels"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["enabled"] != false && c["isRtspEnabled"] == true)
        // A doorbell's package camera is a second lens with a different
        // view, so it must never stand in for the main picture.
        .filter(|c| c["name"] != "Package Camera")
        .filter_map(|c| {
            Some(Channel {
                width: u16::try_from(c["width"].as_u64()?).ok()?,
                height: u16::try_from(c["height"].as_u64()?).ok()?,
                alias: c["rtspAlias"].as_str().filter(|a| !a.is_empty())?.to_owned(),
            })
        })
        .filter(|c| c.width > 0 && c.height > 0)
        .collect()
}

/// What is known about the console right now, shared with the parts that
/// serve video and snapshots on demand.
#[derive(Default)]
pub struct Live {
    host: String,
    inner: RwLock<LiveInner>,
}

#[derive(Default)]
struct LiveInner {
    /// Present while signed in.
    client: Option<Arc<Client>>,
    rtsps_port: u16,
    channels: HashMap<String, Vec<Channel>>,
    /// Which camera each accessory is.
    cameras: HashMap<u64, String>,
}

impl Live {
    fn update(&self, client: Arc<Client>, bootstrap: &Value) {
        let mut inner = self.inner.write().unwrap();
        inner.client = Some(client);
        inner.rtsps_port = bootstrap["nvr"]["ports"]["rtsps"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(7441);
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

/// Reads one camera's video from the console.
struct ProtectVideo {
    live: Arc<Live>,
    camera: String,
}

impl VideoSource for ProtectVideo {
    fn input_args(&self, width: u16) -> Option<Vec<String>> {
        let inner = self.live.inner.read().unwrap();
        let mut available: Vec<&Channel> = inner.channels.get(&self.camera)?.iter().collect();
        available.sort_by_key(|c| c.width);
        // The smallest stream that is at least as wide as asked, else the largest.
        let channel = available.iter().find(|c| c.width >= width).or(available.last())?;
        let url = format!("rtsps://{}:{}/{}?enableSrtp", self.live.host, inner.rtsps_port, channel.alias);
        Some(
            ["-hwaccel", "videotoolbox", "-rtsp_transport", "tcp", "-i", url.as_str()]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
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
    ring: Option<u64>,
    contact: Option<u64>,
    temperature: Option<u64>,
    humidity: Option<u64>,
    light_level: Option<u64>,
    leak: Option<u64>,
    battery_level: Option<u64>,
    low_battery: Option<u64>,
    streams: Vec<StreamIds>,
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
    let sensor = |accessory: &mut Accessory, base: u64, service: &'static str, value: Characteristic| {
        let ids = accessory.add_service_at(base, service, primary.take(), vec![value, status_active()]);
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
    if let (true, Some((width, height))) = (with_video, def.video) {
        let offered = video::resolutions(width, height);
        handles.streams = iid::STREAMS.iter().map(|iid| video::add_stream_service(&mut accessory, *iid, &offered)).collect();
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
    (accessory, handles)
}

/// The Protect devices currently published, and how updates reach them.
#[derive(Default)]
pub struct Devices {
    defs: Vec<DeviceDef>,
    handles: HashMap<(&'static str, String), Handles>,
    /// Set when live video can be served: the shared console state and the
    /// ffmpeg to run.
    video: Option<(Arc<Live>, PathBuf)>,
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
            if let Some((live, ffmpeg)) = &self.video {
                for ids in &handles.streams {
                    let source = Arc::new(ProtectVideo { live: live.clone(), camera: def.id.clone() });
                    video::install(db, aid, *ids, &def.name, source, ffmpeg);
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
            set(h.motion, json!(detected));
        }
        if let (true, Some(iid), true) = (live, h.ring, data["lastRing"].is_number()) {
            tracing::info!("doorbell ring: {}", h.name);
            // 0 is a single press, the only kind a doorbell has.
            db.emit(h.aid, iid, json!(0));
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
        let live = Arc::new(Live { host: config.host.clone(), ..Live::default() });
        let ffmpeg = video::find_ffmpeg();
        if ffmpeg.is_none() {
            tracing::warn!("ffmpeg is not installed, so cameras will have no video");
        }
        let mut devices = Devices { video: ffmpeg.map(|path| (live.clone(), path)), ..Devices::default() };
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
        self.live.clone()
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
        for camera in bootstrap["cameras"].as_array().into_iter().flatten() {
            if channels(camera).is_empty() && camera["isAdopted"] != false {
                tracing::warn!(
                    "{} has no RTSP stream enabled in Protect, so it will have no video",
                    camera["name"].as_str().unwrap_or("a camera")
                );
            }
        }
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
        tracing::info!(
            "connected to UniFi Protect at {} ({} devices)",
            self.config.host,
            self.devices.len()
        );

        let mut updates = client.updates(bootstrap["lastUpdateId"].as_str()).await?;
        while let Some(update) = updates.next().await? {
            self.devices.apply_update(&self.db, &update);
        }
        Ok(())
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
            "nvr": {"ports": {"rtsps": 7441}},
            "cameras": [{
                "id": "cam1", "mac": "AA01", "name": "Front Door", "type": "UVC G4 Doorbell Pro", "state": "CONNECTED",
                "featureFlags": {"isDoorbell": true},
                "channels": [
                    {"id": 0, "name": "High", "enabled": true, "isRtspEnabled": true, "rtspAlias": "HIGH", "width": 1600, "height": 1200},
                    {"id": 1, "name": "Medium", "enabled": true, "isRtspEnabled": true, "rtspAlias": "MED", "width": 960, "height": 720},
                    {"id": 2, "name": "Low", "enabled": true, "isRtspEnabled": false, "rtspAlias": "LOW", "width": 480, "height": 360},
                    {"id": 3, "name": "Package Camera", "enabled": true, "isRtspEnabled": true, "rtspAlias": "PKG", "width": 1600, "height": 1200}
                ]
            }]
        })
    }

    #[test]
    fn camera_video_uses_rtsp_channels_and_never_the_package_camera() {
        let bootstrap = doorbell_with_channels();
        let defs = definitions(&bootstrap);
        assert_eq!(defs[0].video, Some((1600, 1200)));
        // A camera with no RTSP stream offers no video.
        assert_eq!(definitions(&super::tests::bootstrap())[0].video, None);

        let live = Arc::new(Live { host: "10.0.0.5".into(), ..Live::default() });
        let source = ProtectVideo { live: live.clone(), camera: "cam1".into() };
        assert!(source.input_args(1280).is_none(), "nothing is available before the console is reached");

        let pin: Fingerprint = "00".repeat(32).parse().unwrap();
        live.update(Arc::new(Client::new("10.0.0.5", 443, pin)), &bootstrap);
        let url = |width| source.input_args(width).unwrap().pop().unwrap();
        assert_eq!(url(640), "rtsps://10.0.0.5:7441/MED?enableSrtp");
        assert_eq!(url(960), "rtsps://10.0.0.5:7441/MED?enableSrtp");
        assert_eq!(url(1280), "rtsps://10.0.0.5:7441/HIGH?enableSrtp");
        assert_eq!(url(1920), "rtsps://10.0.0.5:7441/HIGH?enableSrtp", "falls back to the largest");
        assert!(!url(1600).contains("PKG") && !url(1600).contains("LOW"));

        live.disconnected();
        assert!(source.input_args(640).is_none());
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
        let rings: Vec<_> = std::iter::from_fn(|| changes.try_recv().ok()).collect();
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
