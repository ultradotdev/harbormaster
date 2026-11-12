//! The optional `config.toml` in the state directory.
//!
//! It never holds secrets: passwords live in the macOS Keychain.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

pub const FILE_NAME: &str = "config.toml";

pub const EXAMPLE: &str = "\
[protect]
host = \"192.0.2.10\"        # address of the console running UniFi Protect
username = \"harbormaster\"  # a local-only account created for Harbormaster
# fingerprint = \"...\"      # added after the first protect-check
# devices = [\"Front Door\"] # publish only these (by name); omit for all
# name_prefix = \"\"         # put before every name sent to HomeKit
# name_suffix = \" HM\"      # put after every name sent to HomeKit
";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub protect: Option<Protect>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protect {
    pub host: String,
    #[serde(default = "https_port")]
    pub port: u16,
    pub username: String,
    /// SHA-256 fingerprint of the console's certificate. Connections are
    /// refused unless the console presents exactly this certificate.
    pub fingerprint: Option<String>,
    /// If set, only these devices are published to HomeKit. Entries match a
    /// device's name (ignoring case), its Protect id or its MAC address.
    pub devices: Option<Vec<String>>,
    /// Text put before and after every device name sent to HomeKit, to
    /// tell these accessories apart from the same devices added another way.
    #[serde(default)]
    pub name_prefix: String,
    #[serde(default)]
    pub name_suffix: String,
}

impl Protect {
    fn check(&self) -> Result<()> {
        for (what, text) in [("name_prefix", &self.name_prefix), ("name_suffix", &self.name_suffix)] {
            anyhow::ensure!(text.chars().count() <= 24, "{what} can be at most 24 characters");
            anyhow::ensure!(!text.chars().any(char::is_control), "{what} cannot contain control characters");
        }
        Ok(())
    }
}

fn https_port() -> u16 {
    443
}

pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join(FILE_NAME)
}

/// Loads the config, treating a missing file as an empty one.
pub fn load(state_dir: &Path) -> Result<Config> {
    let path = path(state_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text).with_context(|| format!("in {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub(crate) fn parse(text: &str) -> Result<Config> {
    let config: Config = toml::from_str(text)?;
    if let Some(protect) = &config.protect {
        protect.check()?;
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses_with_defaults() {
        let config = parse(EXAMPLE).unwrap();
        let protect = config.protect.unwrap();
        assert_eq!((protect.host.as_str(), protect.port, protect.username.as_str()), ("192.0.2.10", 443, "harbormaster"));
        assert!(protect.fingerprint.is_none() && protect.devices.is_none());
        let filtered = parse("[protect]\nhost = \"h\"\nusername = \"u\"\ndevices = [\"Front Door\"]\n").unwrap();
        assert_eq!(filtered.protect.unwrap().devices.unwrap(), ["Front Door"]);

        let plain = parse("[protect]\nhost = \"h\"\nusername = \"u\"\n").unwrap().protect.unwrap();
        assert_eq!((plain.name_prefix.as_str(), plain.name_suffix.as_str()), ("", ""));
        let named = parse("[protect]\nhost = \"h\"\nusername = \"u\"\nname_prefix = \"UP \"\nname_suffix = \" HM\"\n");
        let named = named.unwrap().protect.unwrap();
        assert_eq!((named.name_prefix.as_str(), named.name_suffix.as_str()), ("UP ", " HM"));
        let long = format!("[protect]\nhost = \"h\"\nusername = \"u\"\nname_suffix = \"{}\"\n", "x".repeat(25));
        assert!(parse(&long).is_err());
        assert!(parse("[protect]\nhost = \"h\"\nusername = \"u\"\nname_prefix = \"a\\tb\"\n").is_err());
        assert!(parse("").unwrap().protect.is_none());
    }

    #[test]
    fn typos_and_stray_secrets_are_rejected() {
        assert!(parse("[protect]\nhost = \"h\"\nusernme = \"u\"\n").is_err());
        assert!(parse("[protect]\nhost = \"h\"\nusername = \"u\"\npassword = \"p\"\n").is_err());
    }
}
