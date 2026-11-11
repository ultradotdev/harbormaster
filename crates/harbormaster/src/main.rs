//! Harbormaster bridge daemon.
//!
//! For now this publishes the bridge plus an optional demo temperature
//! sensor, which is enough to prove pairing and events against the Home app.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use harbormaster_hap::model::kind;
use harbormaster_hap::{Accessory, Bridge, Characteristic, Config, Database, Format, Info, Store};
use serde_json::json;

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Args {
    state_dir: PathBuf,
    listen: SocketAddr,
    demo: bool,
}

fn default_state_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set; pass --state-dir")?;
    Ok(PathBuf::from(home).join("Library/Application Support/harbormaster"))
}

fn parse_args() -> Result<Args> {
    let mut args = Args { state_dir: default_state_dir()?, listen: "0.0.0.0:51826".parse()?, demo: false };
    let mut input = std::env::args().skip(1);
    while let Some(flag) = input.next() {
        let mut value = || input.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--state-dir" => args.state_dir = value()?.into(),
            "--listen" => args.listen = value()?.parse().context("--listen expects ADDRESS:PORT")?,
            "--demo" => args.demo = true,
            "--help" | "-h" => {
                println!(
                    "harbormaster {VERSION}\n\n\
                     Options:\n  \
                     --state-dir DIR   where pairing state lives\n  \
                     --listen ADDR     address and port to serve HomeKit on (default 0.0.0.0:51826)\n  \
                     --demo            publish a simulated temperature sensor"
                );
                std::process::exit(0);
            }
            other => bail!("unknown option {other}; try --help"),
        }
    }
    Ok(args)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let args = parse_args()?;

    let store = Arc::new(Store::open(args.state_dir.join("state.json"))?);
    let device_id = store.device_id();
    let name = format!("Harbormaster {}", device_id[12..].replace(':', ""));

    let db = Database::new();
    let mut bridge = Accessory::new(
        1,
        &Info {
            name: &name,
            manufacturer: "Harbormaster",
            model: "Bridge",
            serial_number: &device_id,
            firmware_revision: VERSION,
        },
    );
    bridge.add_service(
        kind::PROTOCOL_INFORMATION,
        false,
        vec![Characteristic::text(kind::VERSION, "1.1.0")],
    );
    db.add(bridge);

    if args.demo {
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
    }

    let config = Config { name: name.clone(), model: "Harbormaster".into(), listen: args.listen, advertise: true };
    let bridge = Bridge::start(config, store.clone(), db).await?;
    tracing::info!("{name} listening on {}", bridge.local_addr);
    if store.is_paired() {
        tracing::info!("already paired with {} controller(s)", store.pairings().len());
    } else {
        tracing::info!("not paired; add it in the Home app with setup code {}", store.setup_code());
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
