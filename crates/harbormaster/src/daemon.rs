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
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::control::{self, Message, Reading, State};
use crate::protect_bridge::ProtectBridge;
use crate::config;
use crate::logbuf::LogBuffer;

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
    let protect = match config::load(&options.state_dir)?.protect {
        Some(protect) => Some(ProtectBridge::prepare(&options.state_dir, protect, store.clone(), db.clone())?),
        None => None,
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

    let daemon = Arc::new(Daemon { name, started: Instant::now(), store, db, bridge, logs });
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
fn create_private_dir(dir: &Path) -> Result<()> {
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
    async fn serve_client(&self, mut stream: UnixStream) -> std::io::Result<()> {
        async fn send(stream: &mut UnixStream, message: &Message) -> std::io::Result<()> {
            let mut line = serde_json::to_vec(message).expect("control messages serialize");
            line.push(b'\n');
            stream.write_all(&line).await
        }

        let (backlog, mut live) = self.logs.attach();
        send(&mut stream, &Message::State(self.state())).await?;
        for line in backlog {
            send(&mut stream, &Message::Log(line)).await?;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = tick.tick() => send(&mut stream, &Message::State(self.state())).await?,
                line = live.recv() => match line {
                    Ok(line) => send(&mut stream, &Message::Log(line)).await?,
                    // A slow TUI just misses some lines.
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                },
            }
        }
    }

    fn state(&self) -> State {
        let paired = self.store.is_paired();
        let now = SystemTime::now();
        State {
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
            accessories: accessories(&self.db.to_json()),
        }
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
    fn mapped_ipv4_peers_display_as_ipv4() {
        assert_eq!(display_ip("::ffff:10.0.0.5".parse().unwrap()), "10.0.0.5");
        assert_eq!(display_ip("fe80::1".parse().unwrap()), "fe80::1");
    }
}
