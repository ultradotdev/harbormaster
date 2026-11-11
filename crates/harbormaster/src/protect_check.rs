//! `harbormaster protect-check`: walks through connecting to UniFi Protect
//! and prints what Harbormaster can see, without changing anything.

use std::path::Path;

use anyhow::{bail, Context, Result};
use harbormaster_protect::{fetch_fingerprint, Client, Fingerprint};

use crate::{config, keychain};

pub async fn run(state_dir: &Path) -> Result<()> {
    let config_path = config::path(state_dir);
    let Some(protect) = config::load(state_dir)?.protect else {
        bail!(
            "UniFi Protect is not configured. Add this to {}:\n\n{}",
            config_path.display(),
            config::EXAMPLE
        );
    };

    let Some(pinned) = &protect.fingerprint else {
        let seen = fetch_fingerprint(&protect.host, protect.port)
            .await
            .with_context(|| format!("connecting to {}:{}", protect.host, protect.port))?;
        println!("The console at {} presents a certificate with this fingerprint:\n", protect.host);
        println!("    {seen}\n");
        println!("If that is your console, trust it by adding this line under [protect] in");
        println!("{}:\n", config_path.display());
        println!("    fingerprint = \"{seen}\"\n");
        println!("Nothing was sent to the console. Run protect-check again afterwards.");
        return Ok(());
    };
    let pin: Fingerprint = pinned.parse().context("fingerprint in config.toml")?;

    let password = keychain::password(keychain::PROTECT_SERVICE, &protect.username)?;
    let mut client = Client::new(&protect.host, protect.port, pin);
    client.login(&protect.username, &password).await?;
    drop(password);
    println!("Signed in to {} as {}.", protect.host, protect.username);

    let bootstrap = client.bootstrap().await?;
    let nvr = &bootstrap.nvr;
    println!(
        "{} ({}), Protect {}\n",
        nvr.name.as_deref().unwrap_or("Unnamed console"),
        nvr.model,
        nvr.version
    );
    println!("{:<28} {:<26} {:<13} {:<6} NOTES", "CAMERA", "MODEL", "STATE", "CODEC");
    for camera in &bootstrap.cameras {
        let flags = &camera.feature_flags;
        let mut notes = Vec::new();
        if flags.is_doorbell {
            notes.push("doorbell".to_owned());
        }
        if flags.has_package_camera {
            notes.push("package camera".to_owned());
        }
        if !flags.smart_detect_types.is_empty() {
            notes.push(format!("detects {}", flags.smart_detect_types.join("/")));
        }
        println!(
            "{:<28} {:<26} {:<13} {:<6} {}",
            camera.device.display_name(),
            camera.device.market_name.as_deref().unwrap_or(&camera.device.model),
            camera.device.state.to_lowercase(),
            camera.video_codec.as_deref().unwrap_or("?"),
            notes.join(", ")
        );
    }
    println!(
        "\n{} cameras, {} lights, {} sensors, {} chimes",
        bootstrap.cameras.len(),
        bootstrap.lights.len(),
        bootstrap.sensors.len(),
        bootstrap.chimes.len()
    );
    Ok(())
}
