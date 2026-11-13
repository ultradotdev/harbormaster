//! `harbormaster protect-check`: walks through connecting to UniFi Protect
//! and prints what Harbormaster can see, without changing anything.

use std::path::Path;

use anyhow::{bail, Context, Result};
use harbormaster_protect::{fetch_fingerprint, Client, Fingerprint};

use crate::{config, secrets};

/// Signs in using the configured console, or explains what is missing.
/// `Ok(None)` means the certificate is not trusted yet and instructions
/// were printed.
async fn sign_in(state_dir: &Path) -> Result<Option<(Client, config::Protect)>> {
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
        return Ok(None);
    };
    let pin: Fingerprint = pinned.parse().context("fingerprint in config.toml")?;

    let password = secrets::protect_password(state_dir, &protect.username)?;
    let mut client = Client::new(&protect.host, protect.port, pin);
    client.login(&protect.username, &password).await?;
    drop(password);
    Ok(Some((client, protect)))
}

pub async fn run(state_dir: &Path) -> Result<()> {
    let Some((client, protect)) = sign_in(state_dir).await? else { return Ok(()) };
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

/// Top-level parts of the bootstrap document worth keeping in a capture.
const CAPTURE_SECTIONS: [&str; 9] =
    ["nvr", "cameras", "lights", "sensors", "chimes", "viewers", "bridges", "doorlocks", "lastUpdateId"];

/// Field names, lowercased, that mark a value as secret or personal.
const SENSITIVE: [&str; 21] = [
    "password", "token", "secret", "credential", "apikey", "accesskey", "privatekey", "psk", "ssid",
    "email", "rtspalias", "latitude", "longitude", "certificate", "publicip", "wanip", "firstname",
    "lastname", "username", "cloudaccount", "lastloginip",
];

/// Removes secrets and personal details from captured console data.
fn redact(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|key, _| {
                let key = key.to_lowercase();
                !SENSITIVE.iter().any(|s| key.contains(s))
            });
            map.values_mut().for_each(redact);
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact),
        _ => {}
    }
}

/// The folder captures go in, for its owner only like the state directory
/// around it.
fn capture_dir(state_dir: &Path) -> Result<std::path::PathBuf> {
    let dir = state_dir.join("protect-capture");
    crate::daemon::create_private_dir(&dir)?;
    Ok(dir)
}

/// Creates or empties a capture file that only its owner can read. What is
/// captured is redacted, but it still describes a home and may show it.
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    // The mode above only applies to a file that did not exist yet.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// `harbormaster protect-capture`: records the device inventory and a
/// sample of realtime updates to files, for developing against real data.
pub async fn capture(state_dir: &Path, seconds: u64) -> Result<()> {
    use std::io::Write;
    let Some((client, protect)) = sign_in(state_dir).await? else { return Ok(()) };
    let dir = capture_dir(state_dir)?;

    let mut bootstrap = client.bootstrap_raw().await?;
    let last_update_id = bootstrap["lastUpdateId"].as_str().map(str::to_owned);
    if let Some(map) = bootstrap.as_object_mut() {
        map.retain(|key, _| CAPTURE_SECTIONS.contains(&key.as_str()));
    }
    redact(&mut bootstrap);
    let bootstrap_path = dir.join("bootstrap.json");
    create_private(&bootstrap_path)
        .and_then(|mut file| file.write_all(&serde_json::to_vec_pretty(&bootstrap)?))
        .with_context(|| format!("writing {}", bootstrap_path.display()))?;
    println!("Signed in to {}. Wrote {}", protect.host, bootstrap_path.display());

    let updates_path = dir.join("updates.jsonl");
    let mut file = create_private(&updates_path)
        .with_context(|| format!("creating {}", updates_path.display()))?;
    let mut stream = client.updates(last_update_id.as_deref()).await?;
    println!("Recording updates for {seconds} seconds. Trigger some motion or ring the doorbell.");
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let mut count = 0u32;
    loop {
        let update = match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) => break,
            Ok(Ok(Some(update))) => update,
            Ok(Ok(None)) => {
                println!("The console closed the stream.");
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
        };
        // Account changes and sign-in records are about people, not devices.
        if update.model_key == "user" || update.data["type"] == "access" {
            continue;
        }
        let mut data = update.data;
        redact(&mut data);
        let line = serde_json::json!({
            "t": started.elapsed().as_secs_f64(),
            "action": update.action,
            "modelKey": update.model_key,
            "id": update.id,
            "data": data,
        });
        writeln!(file, "{line}").with_context(|| format!("writing {}", updates_path.display()))?;
        count += 1;
    }
    println!("Recorded {count} updates to {}", updates_path.display());
    Ok(())
}

/// `harbormaster protect-feed`: records a few seconds of a camera's native
/// live feed to a playable file and reports how the feed behaved.
pub async fn feed(state_dir: &Path, camera: Option<&str>, channel: u8, lens: u8, seconds: u64) -> Result<()> {
    use harbormaster_protect::{FeedOptions, Segment};
    use std::io::Write;
    let Some((client, protect)) = sign_in(state_dir).await? else { return Ok(()) };
    let bootstrap = client.bootstrap().await?;
    let wanted = camera.map(str::to_owned).or_else(|| protect.devices.as_ref()?.first().cloned());
    let Some(wanted) = wanted else { bail!("say which camera with --camera NAME") };
    let Some(found) = bootstrap
        .cameras
        .iter()
        .find(|c| c.device.display_name().eq_ignore_ascii_case(&wanted) || c.device.id == wanted)
    else {
        bail!("no camera named {wanted}; protect-check lists them");
    };
    let name = found.device.display_name();
    for c in &found.channels {
        println!("channel {}: {} {}x{} at {} fps{}", c.id, c.name, c.width, c.height, c.fps, if c.enabled { "" } else { " (off)" });
    }

    let dir = capture_dir(state_dir)?;
    let path = dir.join(format!("feed-{channel}-lens{lens}.mp4"));
    let mut file = create_private(&path).with_context(|| format!("creating {}", path.display()))?;

    let started = std::time::Instant::now();
    let mut stream = client.livestream(&found.device.id, FeedOptions { channel, lens, ..Default::default() }).await?;
    println!("{name}: feed for channel {channel}, lens {lens} opened after {:.0} ms", started.elapsed().as_secs_f64() * 1000.0);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let (mut fragments, mut bytes, mut largest) = (0u64, 0u64, 0usize);
    let (mut first, mut last) = (None, started);
    let mut longest_gap = std::time::Duration::ZERO;
    loop {
        let segment = match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) => break,
            Ok(Ok(Some(segment))) => segment,
            Ok(Ok(None)) => {
                println!("The console closed the feed.");
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
        };
        let at = started.elapsed().as_secs_f64() * 1000.0;
        let data = match &segment {
            Segment::Init { codec, data } => {
                println!("{at:>7.0} ms  header, {} bytes, codec {}", data.len(), codec.as_deref().unwrap_or("not given"));
                data
            }
            Segment::Media(data) => {
                let now = std::time::Instant::now();
                if first.is_none() {
                    println!("{at:>7.0} ms  first fragment, {} bytes", data.len());
                    first = Some(now);
                } else {
                    longest_gap = longest_gap.max(now - last);
                }
                last = now;
                fragments += 1;
                largest = largest.max(data.len());
                data
            }
        };
        bytes += data.len() as u64;
        file.write_all(data).with_context(|| format!("writing {}", path.display()))?;
    }
    let span = first.map_or(0.0, |f| (last - f).as_secs_f64());
    println!(
        "{fragments} fragments over {span:.1} s ({:.0} ms apart on average, longest gap {:.0} ms), {} kB, largest {} bytes",
        if fragments > 1 { span * 1000.0 / (fragments - 1) as f64 } else { 0.0 },
        longest_gap.as_secs_f64() * 1000.0,
        bytes / 1000,
        largest
    );
    println!("frames seen: {:?}", stream.counts());
    println!("Wrote {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_files_are_readable_by_their_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let state = std::env::temp_dir().join(format!("hm-check-{}-capture-mode", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).unwrap();
        let dir = capture_dir(&state).unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        // One left by a build that wrote it for anyone to read.
        let path = dir.join("bootstrap.json");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(create_private(&path).unwrap());
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"", "and it starts empty");
        std::fs::remove_dir_all(&state).unwrap();
    }

    #[test]
    fn redaction_removes_secrets_at_any_depth_and_keeps_the_rest() {
        let mut value = serde_json::json!({
            "name": "Front Door",
            "modelKey": "camera",
            "accessKey": "abc",
            "wifi": {"ssid": "home", "signalStrength": -50},
            "channels": [{"id": 0, "rtspAlias": "xyz", "width": 1920}],
            "user": {"Email": "a@b.c", "authToken": "t", "id": "u1"}
        });
        redact(&mut value);
        assert_eq!(
            value,
            serde_json::json!({
                "name": "Front Door",
                "modelKey": "camera",
                "wifi": {"signalStrength": -50},
                "channels": [{"id": 0, "width": 1920}],
                "user": {"id": "u1"}
            })
        );
    }
}
