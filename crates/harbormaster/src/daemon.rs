//! The long-running bridge process. It owns the HomeKit server and serves
//! status to any attached TUI over a Unix socket in the state directory.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use harbormaster_hap::model::kind;
use harbormaster_hap::{Accessory, Bridge, Characteristic, Config, Database, Format, Info, Store};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::control::{self, Command, Message, Reading, State};
use crate::overrides::{self, Overrides};
use crate::status;
use crate::protect_bridge::ProtectBridge;
use crate::config;
use crate::logbuf::LogBuffer;
use crate::password::{Outcome, Secret, Vault};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// HomeKit accessory category for a bridge.
const CATEGORY_BRIDGE: u8 = 2;

pub struct Options {
    pub state_dir: PathBuf,
    pub listen: SocketAddr,
    pub demo: bool,
}

struct Daemon {
    name: String,
    started: Instant,
    store: Arc<Store>,
    db: Arc<Database>,
    bridge: Arc<Bridge>,
    logs: LogBuffer,
    /// Where the UniFi Protect console is, if one is configured.
    console_host: Option<String>,
    /// Holds the Protect password. Absent when no console is configured.
    vault: Option<Arc<Vault>>,
}

pub async fn run(options: Options, logs: LogBuffer) -> Result<()> {
    create_private_dir(&options.state_dir)?;
    // Claim the control socket first: it doubles as the single-instance lock.
    let socket = bind_control_socket(&options.state_dir.join(control::SOCKET_NAME)).await?;

    let store = Arc::new(Store::open(options.state_dir.join("state.json"))?);
    let device_id = store.device_id();
    let name = format!("Harbormaster {}", device_id[12..].replace(':', ""));

    let db = Database::new();
    let mut bridge_accessory = Accessory::new(
        1,
        &Info {
            name: &name,
            manufacturer: "Harbormaster",
            model: "Bridge",
            serial_number: &device_id,
            firmware_revision: VERSION,
        },
    );
    bridge_accessory.add_service(
        kind::PROTOCOL_INFORMATION,
        false,
        vec![Characteristic::text(kind::VERSION, "1.1.0")],
    );
    db.add(bridge_accessory);
    if options.demo {
        add_demo_sensor(&store, &db)?;
    }
    // Publish known Protect devices before HomeKit can connect, so that a
    // restart never looks like the accessories were removed.
    status::watch(status::global(), &db);
    overrides::init(&options.state_dir);
    let protect = config::load(&options.state_dir)?.protect;
    let console_host = protect.as_ref().map(|p| p.host.clone());
    // With no real console, the demo brings a pretend one.
    let fleet = if options.demo && protect.is_none() { crate::demo::Fleet::publish(&store, &db)? } else { None };
    let console_host = console_host.or(fleet.as_ref().map(|_| crate::demo::CONSOLE.to_owned()));
    // The password is looked for once, here. With none to be found the
    // bridge still starts and waits for `harbormaster unlock`.
    let vault = protect.as_ref().map(|p| Vault::new(crate::secrets::at_start(&options.state_dir, &p.username)));
    let protect = match (protect, &vault) {
        (Some(protect), Some(vault)) => {
            Some(ProtectBridge::prepare(&options.state_dir, protect, store.clone(), db.clone(), vault.clone())?)
        }
        _ => None,
    };

    let config =
        Config { name: name.clone(), model: "Harbormaster".into(), listen: options.listen,
        advertise: true,
        snapshots: protect.as_ref().map(|p| p.snapshots()),
    };
    let bridge = Arc::new(Bridge::start(config, store.clone(), db.clone()).await?);
    tracing::info!("{name} listening on {}", bridge.local_addr);
    if store.is_paired() {
        tracing::info!("paired with {} controller(s)", store.pairings().len());
    } else {
        print_setup(&store);
    }

    if let Some(protect) = protect {
        tokio::spawn(protect.run(bridge.clone()));
    }
    if let Some(fleet) = fleet {
        tokio::spawn(fleet.run(bridge.clone()));
    }

    let daemon = Arc::new(Daemon { name, started: Instant::now(), store, db, bridge, logs, console_host, vault });
    let serving = daemon.clone();
    tokio::spawn(async move {
        loop {
            match socket.accept().await {
                Ok((stream, _)) => {
                    let daemon = serving.clone();
                    tokio::spawn(async move {
                        // A TUI detaching is normal; nothing to report.
                        let _ = daemon.serve_client(stream).await;
                    });
                }
                Err(e) => {
                    tracing::warn!("control socket accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    });

    wait_for_shutdown().await?;
    tracing::info!("shutting down");
    let _ = std::fs::remove_file(options.state_dir.join(control::SOCKET_NAME));
    Ok(())
}

async fn wait_for_shutdown() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    // launchd stops services with SIGTERM; Ctrl-C sends SIGINT.
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {}
    }
    Ok(())
}

/// The state directory holds pairing keys, so only the owner may enter it.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {}", dir.display()))
}

/// Longest Unix socket path macOS accepts, including the terminating NUL.
const MAX_SOCKET_PATH: usize = 104;

async fn bind_control_socket(path: &Path) -> Result<UnixListener> {
    if path.as_os_str().len() >= MAX_SOCKET_PATH {
        bail!(
            "state directory path is too long for the control socket ({} is over {} bytes); \
             choose a shorter --state-dir",
            path.display(),
            MAX_SOCKET_PATH - 1
        );
    }
    if UnixStream::connect(path).await.is_ok() {
        bail!("another Harbormaster daemon is already running with this state directory");
    }
    // Nothing answered, so any file here is left over from a crashed daemon.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing stale {}", path.display())),
    }
    let listener = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // The directory is already private; restrict the socket itself as well.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;
    Ok(listener)
}

fn add_demo_sensor(store: &Store, db: &Arc<Database>) -> Result<()> {
    let aid = store.accessory_id("demo:temperature")?;
    let mut sensor = Accessory::new(
        aid,
        &Info {
            name: "Demo Temperature",
            manufacturer: "Harbormaster",
            model: "Demo",
            serial_number: "demo-1",
            firmware_revision: VERSION,
        },
    );
    let ids = sensor.add_service(
        kind::TEMPERATURE_SENSOR,
        true,
        vec![Characteristic::sensor(kind::CURRENT_TEMPERATURE, Format::Float, json!(20.0))
            .unit("celsius")
            .range(-100.0, 100.0, 0.1)],
    );
    db.add(sensor);
    let (db, iid) = (db.clone(), ids[0]);
    tokio::spawn(async move {
        let mut tick = 0u32;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            tick += 1;
            // A slow triangle wave between 18.0 and 23.0 degrees.
            let step = (tick % 20) as f64;
            let value = 18.0 + if step < 10.0 { step } else { 20.0 - step } * 0.5;
            db.set(aid, iid, json!(value));
        }
    });
    Ok(())
}

/// Shows the setup code and a scannable QR code for pairing.
fn print_setup(store: &Store) {
    println!("\nNot paired. In the Home app choose Add Accessory, then scan this code");
    println!("or enter the setup code manually.\n");
    match crate::qr::render(&store.setup_uri(CATEGORY_BRIDGE)) {
        Some(code) => println!("{code}"),
        None => tracing::warn!("could not draw QR code"),
    }
    println!("\nSetup code: {}\n", store.setup_code());
}

impl Daemon {
    async fn serve_client(&self, stream: UnixStream) -> std::io::Result<()> {
        async fn send(stream: &mut tokio::net::unix::OwnedWriteHalf, message: &Message) -> std::io::Result<()> {
            let mut line = serde_json::to_vec(message).expect("control messages serialize");
            line.push(b'\n');
            stream.write_all(&line).await
        }

        let (requests, mut stream) = stream.into_split();
        // Requests are a few dozen bytes each. The cap on what one
        // attachment may send keeps a runaway client from filling memory;
        // a TUI that reaches it is dropped and simply attaches again.
        let mut requests = BufReader::new(tokio::io::AsyncReadExt::take(requests, 1 << 20)).lines();
        let (backlog, mut live) = self.logs.attach();
        send(&mut stream, &Message::State(Box::new(self.state()))).await?;
        for line in backlog {
            send(&mut stream, &Message::Log(line)).await?;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        // Set while this client waits to hear how its unlock went.
        let mut unlocking: Option<tokio::sync::oneshot::Receiver<Outcome>> = None;
        loop {
            tokio::select! {
                outcome = async { unlocking.as_mut().expect("guarded").await }, if unlocking.is_some() => {
                    unlocking = None;
                    let outcome = outcome.unwrap_or_else(|_| Outcome::Failed("the daemon gave no answer".into()));
                    send(&mut stream, &Message::Unlock(unlock_reply(outcome))).await?;
                    send(&mut stream, &Message::State(Box::new(self.state()))).await?;
                },
                _ = tick.tick() => send(&mut stream, &Message::State(Box::new(self.state()))).await?,
                line = live.recv() => match line {
                    Ok(line) => send(&mut stream, &Message::Log(line)).await?,
                    // A slow TUI just misses some lines.
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                },
                request = requests.next_line() => match request? {
                    Some(mut line) => {
                        // A request this build does not know is ignored.
                        let command = serde_json::from_str::<Command>(&line);
                        // The line may carry a password; do not leave it lying about.
                        zeroize::Zeroize::zeroize(&mut line);
                        if let Ok(Command::Unlock { password }) = command {
                            unlocking = Some(self.unlock(password));
                        } else if let Ok(command) = command {
                            let connected = status::global().snapshot().console_connected;
                            match run_command(overrides::global(), connected, &command) {
                                Ok(done) => tracing::info!("{done}"),
                                Err(why) => tracing::warn!("{why}"),
                            }
                            send(&mut stream, &Message::State(Box::new(self.state()))).await?;
                        }
                    }
                    None => return Ok(()),
                },
            }
        }
    }

    /// Takes a password handed over by the owner. The receiver hears how
    /// the sign-in went.
    fn unlock(&self, password: Secret) -> tokio::sync::oneshot::Receiver<Outcome> {
        match &self.vault {
            Some(vault) => {
                tracing::info!("the Protect password was handed over from a terminal");
                vault.offer(password)
            }
            None => {
                let (answer, outcome) = tokio::sync::oneshot::channel();
                let _ = answer.send(Outcome::Failed("no UniFi Protect console is configured".into()));
                outcome
            }
        }
    }

    fn state(&self) -> State {
        let paired = self.store.is_paired();
        let now = SystemTime::now();
        let board = status::global().snapshot();
        let database = self.db.to_json();
        let affix = overrides::affix().unwrap_or_default();
        State {
            time: now.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
            config_number: self.store.config_number(),
            pid: std::process::id(),
            console: self.console_host.as_ref().map(|host| {
                console(host, &board, self.vault.as_ref().map(|vault| vault.view()).unwrap_or_default())
            }),
            devices: devices(&database, &board, overrides::global().map(Overrides::list).unwrap_or_default(), &affix),
            name_prefix: affix.0.clone(),
            name_suffix: affix.1.clone(),
            detect_everywhere: overrides::global()
                .map(|o| o.sensors_everywhere().into_iter().map(|d| d.word().to_owned()).collect())
                .unwrap_or_default(),
            name: self.name.clone(),
            version: VERSION.to_owned(),
            listen: self.bridge.local_addr.to_string(),
            uptime_secs: self.started.elapsed().as_secs(),
            paired,
            setup_code: (!paired).then(|| self.store.setup_code()),
            setup_uri: (!paired).then(|| self.store.setup_uri(CATEGORY_BRIDGE)),
            controllers: self
                .store
                .pairings()
                .into_iter()
                .map(|(id, p)| control::Controller { id, admin: p.admin })
                .collect(),
            connections: self
                .bridge
                .connections()
                .into_iter()
                .map(|c| control::Connection {
                    peer: display_ip(c.peer.ip()),
                    controller: c.controller,
                    connected_secs: now.duration_since(c.connected_at).map_or(0, |d| d.as_secs()),
                })
                .collect(),
            accessories: accessories(&database),
        }
    }
}

/// The console's line in a snapshot. The password itself is never in it,
/// only whether the daemon has one.
fn console(host: &str, board: &status::Snapshot, password: crate::password::View) -> control::Console {
    control::Console {
        host: host.to_owned(),
        connected: board.console_connected,
        last_update: board.console_last_update,
        waiting_for_password: password.waiting,
        problem: if board.console_connected { None } else { password.problem },
    }
}

fn unlock_reply(outcome: Outcome) -> control::UnlockReply {
    match outcome {
        Outcome::SignedIn { devices } => control::UnlockReply { signed_in: true, devices, ..Default::default() },
        Outcome::Rejected(detail) => control::UnlockReply { detail, ..Default::default() },
        Outcome::Failed(detail) => control::UnlockReply { detail, kept: true, ..Default::default() },
    }
}

/// IPv4 peers arrive on the dual-stack socket as `::ffff:a.b.c.d`.
fn display_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(v6.to_string(), |v4| v4.to_string()),
        v4 => v4.to_string(),
    }
}

/// Flattens the HomeKit accessory database into what the TUI shows.
fn accessories(db: &Value) -> Vec<control::Accessory> {
    let empty = Vec::new();
    let list = |v: &'_ Value| -> Vec<Value> { v.as_array().unwrap_or(&empty).clone() };
    list(&db["accessories"])
        .iter()
        .map(|accessory| {
            let mut out = control::Accessory {
                aid: accessory["aid"].as_u64().unwrap_or(0),
                name: String::new(),
                manufacturer: String::new(),
                model: String::new(),
                serial_number: String::new(),
                readings: Vec::new(),
            };
            for service in list(&accessory["services"]) {
                let service_kind = service["type"].as_str().unwrap_or("");
                for c in list(&service["characteristics"]) {
                    let (ty, value) = (c["type"].as_str().unwrap_or(""), &c["value"]);
                    let text = || value.as_str().unwrap_or("").to_owned();
                    match (service_kind, ty) {
                        (kind::ACCESSORY_INFORMATION, kind::NAME) => out.name = text(),
                        (kind::ACCESSORY_INFORMATION, kind::MANUFACTURER) => out.manufacturer = text(),
                        (kind::ACCESSORY_INFORMATION, kind::MODEL) => out.model = text(),
                        (kind::ACCESSORY_INFORMATION, kind::SERIAL_NUMBER) => out.serial_number = text(),
                        (kind::ACCESSORY_INFORMATION | kind::PROTOCOL_INFORMATION, _) => {}
                        _ if value.is_null() => {}
                        // One "Online" row is enough however many services report it.
                        (_, kind::STATUS_ACTIVE) if out.readings.iter().any(|r| r.label == "Online") => {}
                        _ => out.readings.push(reading(ty, value, c["unit"].as_str())),
                    }
                }
            }
            out
        })
        .collect()
}

/// Carries out a request from the terminal interface. Returns what to log:
/// what was done, or why it was not.
fn run_command(overrides: Option<&Overrides>, connected: bool, command: &Command) -> Result<String, String> {
    let overrides = overrides.ok_or("devices cannot be changed: no choices file is loaded")?;
    // The bridge acts on a change when the console next speaks to it.
    let when = if connected { "" } else { "; this takes effect when the console is reachable" };
    match command {
        Command::SetShared { key, shared } => {
            let entry = overrides.set_shared(key, *shared)?;
            let what = if *shared { "will be shared with HomeKit" } else { "will no longer be shared with HomeKit" };
            Ok(format!("{}: {what}, as asked in the terminal{when}", entry.display_name()))
        }
        Command::SetNamePrefix { text } | Command::SetNameSuffix { text } => {
            let (end, what) = match command {
                Command::SetNamePrefix { .. } => (overrides::End::Prefix, "prefix"),
                _ => (overrides::End::Suffix, "suffix"),
            };
            let (prefix, suffix) = overrides.set_affix(end, text.as_deref())?;
            let source = if text.is_some() { "as asked in the terminal" } else { "as config.toml says" };
            Ok(format!("names sent to HomeKit will read \"{prefix}<name>{suffix}\": {what} set {source}{when}"))
        }
        Command::SetDetection { key, detection, on } => {
            let kind = crate::protect_bridge::Detection::parse(detection)
                .ok_or_else(|| format!("{detection} is not something cameras recognise"))?;
            let whose = match overrides.set_sensor(key.as_deref(), kind, *on)? {
                Some(name) => name,
                None => "every camera that can tell".to_owned(),
            };
            let what = if *on { "will have" } else { "will no longer have" };
            Ok(format!("{whose}: {what} a {} sensor in HomeKit, as asked in the terminal{when}", kind.word()))
        }
        Command::Unlock { .. } => Err("a password is not a device setting".into()),
        Command::Rename { key, name } => {
            let entry = overrides.rename(key, name.as_deref())?;
            Ok(match &entry.name {
                Some(name) => format!("{}: will be published as {name}, as asked in the terminal{when}", entry.protect_name),
                None => format!("{}: will be published under its own name again{when}", entry.protect_name),
            })
        }
    }
}

/// Works out what each known device is and what it is doing, from the
/// HomeKit database, the status board and the owner's choices. The bridge
/// itself is left out; devices that are not shared come last.
fn devices(
    db: &Value,
    board: &status::Snapshot,
    choices: Vec<(String, overrides::Entry)>,
    affix: &(String, String),
) -> Vec<control::Device> {
    use harbormaster_hap::camera::kind::CAMERA_RTP_STREAM_MANAGEMENT;
    use harbormaster_hap::recording::kind::{ACTIVE, CAMERA_RECORDING_MANAGEMENT};
    fn list(v: &Value) -> &[Value] {
        v.as_array().map_or(&[], Vec::as_slice)
    }
    let mut out = Vec::new();
    for accessory in list(&db["accessories"]) {
        let aid = accessory["aid"].as_u64().unwrap_or(0);
        let mut device = control::Device { aid, ..control::Device::default() };
        let (mut bridge, mut video, mut doorbell, mut light) = (false, false, false, false);
        for service in list(&accessory["services"]) {
            let service_kind = service["type"].as_str().unwrap_or("");
            match service_kind {
                kind::PROTOCOL_INFORMATION => bridge = true,
                CAMERA_RTP_STREAM_MANAGEMENT => video = true,
                kind::DOORBELL => doorbell = true,
                kind::LIGHTBULB => light = true,
                _ => {}
            }
            for c in list(&service["characteristics"]) {
                let (ty, value) = (c["type"].as_str().unwrap_or(""), &c["value"]);
                let text = || value.as_str().unwrap_or("").to_owned();
                let flag = || value.as_bool().or_else(|| value.as_u64().map(|n| n != 0));
                let percent = || value.as_f64().map(|n| n.clamp(0.0, 100.0).round() as u8);
                match (service_kind, ty) {
                    (kind::ACCESSORY_INFORMATION, kind::NAME) => device.name = text(),
                    (kind::ACCESSORY_INFORMATION, kind::MODEL) => device.model = text(),
                    (kind::ACCESSORY_INFORMATION, kind::SERIAL_NUMBER) => device.serial_number = text(),
                    (kind::ACCESSORY_INFORMATION, _) => {}
                    // Every sensor service repeats these; they always agree.
                    (_, kind::STATUS_ACTIVE) => device.online = device.online.or(flag()),
                    (_, kind::STATUS_TAMPERED) => {
                        device.tampered = Some(device.tampered.unwrap_or(false) || flag().unwrap_or(false))
                    }
                    (_, kind::MOTION_DETECTED) => device.motion = flag(),
                    (kind::LIGHTBULB, kind::ON) => device.light_on = flag(),
                    (kind::LIGHTBULB, kind::BRIGHTNESS) => device.brightness = percent(),
                    (_, kind::BATTERY_LEVEL) => device.battery = percent(),
                    (_, kind::STATUS_LOW_BATTERY) => device.low_battery = flag(),
                    (CAMERA_RECORDING_MANAGEMENT, ACTIVE) => {
                        device.recording =
                            Some(control::Recording { enabled: flag().unwrap_or(false), ..Default::default() })
                    }
                    (
                        _,
                        kind::CURRENT_TEMPERATURE
                        | kind::CURRENT_RELATIVE_HUMIDITY
                        | kind::CURRENT_AMBIENT_LIGHT_LEVEL
                        | kind::CONTACT_SENSOR_STATE
                        | kind::LEAK_DETECTED,
                    ) if !value.is_null() => device.readings.push(reading(ty, value, c["unit"].as_str())),
                    _ => {}
                }
            }
        }
        if bridge {
            continue;
        }
        // HomeKit's copy of the name carries the owner's prefix and suffix.
        // Everything here, like the log, goes by the plain name.
        if board.keys.contains_key(&aid) {
            let plain = device.name.strip_prefix(affix.0.as_str()).unwrap_or(&device.name);
            device.name = plain.strip_suffix(affix.1.as_str()).unwrap_or(plain).to_owned();
        }
        device.kind = match (doorbell, board.kinds.get(&aid).copied()) {
            (true, _) => "doorbell",
            (false, Some(kind)) => kind,
            (false, None) if video => "camera",
            (false, None) if light => "light",
            (false, None) => "sensor",
        }
        .to_owned();
        device.last_motion = board.last_motion.get(&aid).copied();
        device.last_ring = board.last_ring.get(&aid).copied();
        device.viewers = board
            .viewers
            .iter()
            .filter(|v| v.aid == aid)
            .map(|v| control::Viewer { peer: display_ip(v.peer), width: v.width, height: v.height, secs: v.secs })
            .collect();
        // Recordings report by camera name, which is all that code knows.
        let (active, last) = (board.recording.get(&device.name), board.last_recording.get(&device.name));
        if let Some(recording) = device.recording.as_mut() {
            recording.active_secs = active.copied();
            (recording.last_at, recording.last_secs) = (last.map(|l| l.0), last.map(|l| l.1));
        }
        if let Some((key, entry)) = board.keys.get(&aid).and_then(|key| choices.iter().find(|(k, _)| k == key)) {
            device.key = Some(key.clone());
            if !entry.display_name().is_empty() {
                device.name = entry.display_name().to_owned();
            }
            // Still published for the moment it takes the bridge to act.
            device.hidden = entry.hidden;
            device.protect_name = entry.name.as_ref().map(|_| entry.protect_name.clone());
            device.detects = entry.detects.iter().map(|d| d.word().to_owned()).collect();
            device.detect_here = entry.sensors.iter().map(|d| d.word().to_owned()).collect();
        }
        out.push(device);
    }
    for (key, entry) in choices {
        if entry.hidden && !out.iter().any(|d| d.key.as_ref() == Some(&key)) {
            out.push(control::Device {
                name: entry.display_name().to_owned(),
                protect_name: entry.name.as_ref().map(|_| entry.protect_name.clone()),
                kind: entry.kind,
                key: Some(key),
                hidden: true,
                ..control::Device::default()
            });
        }
    }
    out
}

fn reading(ty: &str, value: &Value, unit: Option<&str>) -> Reading {
    let label = match ty {
        kind::CURRENT_TEMPERATURE => "Temperature".to_owned(),
        kind::CURRENT_RELATIVE_HUMIDITY => "Humidity".to_owned(),
        kind::MOTION_DETECTED => "Motion".to_owned(),
        kind::CONTACT_SENSOR_STATE => "Contact".to_owned(),
        kind::LEAK_DETECTED => "Leak".to_owned(),
        kind::CURRENT_AMBIENT_LIGHT_LEVEL => "Light level".to_owned(),
        kind::BATTERY_LEVEL => "Battery".to_owned(),
        kind::STATUS_LOW_BATTERY => "Low battery".to_owned(),
        kind::STATUS_ACTIVE => "Online".to_owned(),
        kind::CHARGING_STATE => "Charging".to_owned(),
        other => format!("Characteristic {other}"),
    };
    let suffix = match unit {
        Some("celsius") => " °C",
        Some("percentage") => " %",
        Some("lux") => " lux",
        _ => "",
    };
    let yes_no = |on: bool| if on { "yes" } else { "no" }.to_owned();
    let value = match (ty, value) {
        (kind::CONTACT_SENSOR_STATE, v) => if v == &json!(1) { "open" } else { "closed" }.to_owned(),
        (kind::LEAK_DETECTED | kind::STATUS_LOW_BATTERY, v) => yes_no(v == &json!(1)),
        (kind::CHARGING_STATE, _) => "not chargeable".to_owned(),
        (_, Value::Bool(on)) => yes_no(*on),
        (_, value) => plain(value, suffix),
    };
    Reading { label, value }
}

fn plain(value: &Value, suffix: &str) -> String {
    match value {
        Value::Number(n) if n.is_f64() => format!("{:.1}{suffix}", n.as_f64().unwrap_or(0.0)),
        Value::String(s) => s.clone(),
        other => format!("{other}{suffix}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A whole unlock as an attached client sees it: the password goes in,
    /// the answer comes back, and nothing the daemon says along the way
    /// (snapshots, log lines) repeats the password.
    #[tokio::test]
    async fn an_unlock_is_answered_and_the_password_is_never_sent_back() {
        use tracing_subscriber::layer::SubscriberExt;
        let logs = LogBuffer::new();
        let _logging = tracing::subscriber::set_default(tracing_subscriber::registry().with(logs.clone()));
        let dir = std::env::temp_dir().join(format!("hm-daemon-{}-unlock", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::open(dir.join("state.json")).unwrap());
        let db = Database::new();
        let config = Config {
            name: "Test".into(),
            model: "Test".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: false,
            snapshots: None,
        };
        let bridge = Arc::new(Bridge::start(config, store.clone(), db.clone()).await.unwrap());
        let vault = Vault::new(None);
        let daemon = Arc::new(Daemon {
            name: "Test".into(),
            started: Instant::now(),
            store,
            db,
            bridge,
            logs,
            console_host: Some("192.0.2.10".into()),
            vault: Some(vault.clone()),
        });
        let waiting = daemon.state().console.unwrap();
        assert!(waiting.waiting_for_password && !waiting.connected);

        let (ours, theirs) = UnixStream::pair().unwrap();
        let serving = daemon.clone();
        let client = tokio::spawn(async move { serving.serve_client(theirs).await });
        let (read, mut write) = ours.into_split();
        let mut lines = BufReader::new(read).lines();
        write.write_all(b"{\"type\":\"unlock\",\"password\":\"correct horse\"}\n").await.unwrap();

        // The bridge's part: take the password and sign in with it.
        let used = vault.password().await;
        assert_eq!(used.expose(), "correct horse");
        vault.signed_in(4);

        let mut heard = String::new();
        let reply = loop {
            let line = lines.next_line().await.unwrap().expect("the daemon hung up");
            heard.push_str(&line);
            if let Ok(Message::Unlock(reply)) = serde_json::from_str(&line) {
                break reply;
            }
        };
        assert_eq!(reply, control::UnlockReply { signed_in: true, devices: 4, ..Default::default() });
        // The snapshot that follows the answer.
        heard.push_str(&lines.next_line().await.unwrap().unwrap());
        assert!(heard.contains("\"waiting_for_password\":true") && heard.contains("\"waiting_for_password\":false"), "{heard}");
        assert!(heard.contains("handed over"), "the hand-over is logged: {heard}");
        assert!(!heard.contains("horse"), "the password came back: {heard}");
        assert!(!format!("{:?}", daemon.state()).contains("horse"));

        // With no console configured there is nothing to unlock.
        client.abort();
        let _ = client.await;
        let nowhere = Daemon { vault: None, console_host: None, ..Arc::into_inner(daemon).expect("the client task is still running") };
        let outcome = nowhere.unlock(Secret::new("x".into())).await.unwrap();
        assert!(matches!(outcome, Outcome::Failed(why) if why.contains("no UniFi Protect console")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flattens_database_for_display() {
        let db = Database::new();
        let info = Info {
            name: "Porch",
            manufacturer: "Acme",
            model: "T1",
            serial_number: "s1",
            firmware_revision: "1",
        };
        let mut accessory = Accessory::new(2, &info);
        accessory.add_service(
            kind::TEMPERATURE_SENSOR,
            true,
            vec![Characteristic::sensor(kind::CURRENT_TEMPERATURE, Format::Float, json!(21.25)).unit("celsius")],
        );
        db.add(accessory);
        let view = accessories(&db.to_json());
        assert_eq!(view.len(), 1);
        assert_eq!((view[0].name.as_str(), view[0].model.as_str()), ("Porch", "T1"));
        assert_eq!(view[0].readings.len(), 1);
        assert_eq!(view[0].readings[0].label, "Temperature");
        assert_eq!(view[0].readings[0].value, "21.2 °C");
    }

    #[test]
    fn devices_combine_the_database_with_the_status_board() {
        use harbormaster_hap::camera::kind::CAMERA_RTP_STREAM_MANAGEMENT;
        use harbormaster_hap::recording::kind::{ACTIVE, CAMERA_RECORDING_MANAGEMENT};
        let db = Database::new();
        let info = |name: &'static str| Info {
            name,
            manufacturer: "Ubiquiti",
            model: "G4",
            serial_number: "AA01",
            firmware_revision: "1",
        };
        let mut bridge = Accessory::new(1, &info("Bridge"));
        bridge.add_service(kind::PROTOCOL_INFORMATION, false, vec![Characteristic::text(kind::VERSION, "1.1.0")]);
        db.add(bridge);

        let mut door = Accessory::new(2, &info("HM Front Door (UP)"));
        door.add_service(
            kind::DOORBELL,
            true,
            vec![Characteristic::sensor(kind::PROGRAMMABLE_SWITCH_EVENT, Format::Uint8, Value::Null)],
        );
        door.add_service(
            kind::MOTION_SENSOR,
            false,
            vec![
                Characteristic::sensor(kind::MOTION_DETECTED, Format::Bool, json!(true)),
                Characteristic::sensor(kind::STATUS_ACTIVE, Format::Bool, json!(true)),
            ],
        );
        door.add_service(CAMERA_RTP_STREAM_MANAGEMENT, false, vec![]);
        door.add_service(
            CAMERA_RECORDING_MANAGEMENT,
            false,
            vec![Characteristic::sensor(ACTIVE, Format::Uint8, json!(1))],
        );
        db.add(door);

        let mut yard = Accessory::new(3, &info("HM Yard (UP)"));
        yard.add_service(
            kind::TEMPERATURE_SENSOR,
            true,
            vec![
                Characteristic::sensor(kind::CURRENT_TEMPERATURE, Format::Float, json!(17.17)).unit("celsius"),
                Characteristic::sensor(kind::STATUS_ACTIVE, Format::Bool, json!(false)),
                Characteristic::sensor(kind::STATUS_TAMPERED, Format::Uint8, json!(1)),
            ],
        );
        yard.add_service(
            kind::BATTERY,
            false,
            vec![
                Characteristic::sensor(kind::BATTERY_LEVEL, Format::Uint8, json!(93)),
                Characteristic::sensor(kind::STATUS_LOW_BATTERY, Format::Uint8, json!(0)),
            ],
        );
        db.add(yard);

        let board = status::Status::new();
        board.device_kind(2, "camera", "protect:camera:cam1");
        board.device_kind(3, "sensor", "protect:sensor:sen2");
        board.ring(2);
        let _viewer = board.viewing(2, "::ffff:10.0.0.5".parse().unwrap(), 1280, 720);
        let _recording = board.recording("Front Door");
        let choices = Overrides::in_memory();
        let known = |kind, id: &str, name: &str| crate::protect_bridge::DeviceDef {
            kind,
            id: id.into(),
            name: name.into(),
            model: String::new(),
            mac: String::new(),
            firmware: String::new(),
            features: Default::default(),
            video: None,
            lens: 0,
        };
        use crate::protect_bridge::Kind;
        choices.apply(
            vec![known(Kind::Camera, "cam1", "Front Door Cam"), known(Kind::Sensor, "sen2", "Yard"), known(Kind::Light, "lit1", "Floodlight")],
            true,
        );
        choices.rename("protect:camera:cam1", Some("Front Door")).unwrap();
        choices.set_shared("protect:light:lit1", false).unwrap();
        let affix = ("HM ".to_owned(), " (UP)".to_owned());
        let view = devices(&db.to_json(), &board.snapshot(), choices.list(), &affix);

        assert_eq!(view.len(), 3, "the bridge itself is not a device");
        assert_eq!(view[0].key.as_deref(), Some("protect:camera:cam1"));
        assert_eq!((view[0].hidden, view[0].protect_name.as_deref()), (false, Some("Front Door Cam")));
        assert_eq!((view[1].key.as_deref(), view[1].protect_name.as_deref()), (Some("protect:sensor:sen2"), None));
        // A device that is not shared is still listed, so it can be shared again.
        let light = &view[2];
        assert_eq!((light.name.as_str(), light.kind.as_str(), light.hidden, light.aid), ("Floodlight", "light", true, 0));
        assert_eq!(light.key.as_deref(), Some("protect:light:lit1"));
        let door = &view[0];
        assert_eq!((door.kind.as_str(), door.name.as_str()), ("doorbell", "Front Door"));
        assert_eq!((door.online, door.motion), (Some(true), Some(true)));
        assert!(door.last_ring.is_some() && door.last_motion.is_none());
        assert_eq!((door.viewers[0].peer.as_str(), door.viewers[0].width), ("10.0.0.5", 1280));
        let recording = door.recording.as_ref().unwrap();
        assert!(recording.enabled && recording.active_secs.is_some() && recording.last_at.is_none());

        let yard = &view[1];
        assert_eq!((yard.kind.as_str(), yard.online, yard.tampered), ("sensor", Some(false), Some(true)));
        assert_eq!(yard.name, "Yard", "names are plain, without HomeKit's prefix and suffix");
        assert_eq!((yard.battery, yard.low_battery), (Some(93), Some(false)));
        assert_eq!(yard.readings[0].value, "17.2 °C");
        assert!(yard.recording.is_none() && yard.viewers.is_empty());
    }

    #[test]
    fn terminal_requests_change_choices_and_say_what_happened() {
        let choices = Overrides::in_memory();
        let def = crate::protect_bridge::DeviceDef {
            kind: crate::protect_bridge::Kind::Camera,
            id: "cam1".into(),
            name: "Front Door".into(),
            model: String::new(),
            mac: String::new(),
            firmware: String::new(),
            features: Default::default(),
            video: None,
            lens: 0,
        };
        choices.apply(vec![def], true);
        let key = "protect:camera:cam1".to_owned();

        let hide = Command::SetShared { key: key.clone(), shared: false };
        assert_eq!(
            run_command(Some(&choices), true, &hide).unwrap(),
            "Front Door: will no longer be shared with HomeKit, as asked in the terminal"
        );
        assert!(choices.is_hidden(&key));
        let rename = Command::Rename { key: key.clone(), name: Some("Porch".into()) };
        let said = run_command(Some(&choices), false, &rename).unwrap();
        assert!(said.starts_with("Front Door: will be published as Porch") && said.contains("when the console is reachable"));
        let restore = Command::Rename { key: key.clone(), name: Some("  ".into()) };
        assert!(run_command(Some(&choices), true, &restore).unwrap().contains("its own name again"));

        // The prefix and suffix, spaces and all.
        let prefix = Command::SetNamePrefix { text: Some("HM ".into()) };
        let said = run_command(Some(&choices), true, &prefix).unwrap();
        assert!(said.contains("\"HM <name>\"") && said.contains("prefix set as asked in the terminal"), "{said}");
        let suffix = Command::SetNameSuffix { text: Some(" (UP)".into()) };
        assert!(run_command(Some(&choices), true, &suffix).unwrap().contains("\"HM <name> (UP)\""));
        assert_eq!(choices.affix(), ("HM ".to_owned(), " (UP)".to_owned()));
        let reset = Command::SetNamePrefix { text: None };
        assert!(run_command(Some(&choices), true, &reset).unwrap().contains("as config.toml says"));
        let long = Command::SetNameSuffix { text: Some("x".repeat(25)) };
        assert!(run_command(Some(&choices), true, &long).is_err());

        let detect = |detection: &str| Command::SetDetection { key: None, detection: detection.into(), on: true };
        let said = run_command(Some(&choices), true, &detect("person")).unwrap();
        assert!(said.contains("every camera that can tell: will have a person sensor"), "{said}");
        assert_eq!(choices.sensors_everywhere(), [crate::protect_bridge::Detection::Person]);
        assert!(run_command(Some(&choices), true, &detect("unicorn")).is_err());

        let unknown = Command::SetShared { key: "protect:camera:nope".into(), shared: false };
        assert!(run_command(Some(&choices), true, &unknown).is_err());
        assert!(run_command(None, true, &hide).is_err());
    }

    #[test]
    fn mapped_ipv4_peers_display_as_ipv4() {
        assert_eq!(display_ip("::ffff:10.0.0.5".parse().unwrap()), "10.0.0.5");
        assert_eq!(display_ip("fe80::1".parse().unwrap()), "fe80::1");
    }
}
