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

fn parse(text: &str) -> Result<Config> {
    Ok(toml::from_str(text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses_with_defaults() {
        let config = parse(EXAMPLE).unwrap();
        let protect = config.protect.unwrap();
        assert_eq!((protect.host.as_str(), protect.port, protect.username.as_str()), ("192.0.2.10", 443, "harbormaster"));
        assert!(protect.fingerprint.is_none());
        assert!(parse("").unwrap().protect.is_none());
    }

    #[test]
    fn typos_and_stray_secrets_are_rejected() {
        assert!(parse("[protect]\nhost = \"h\"\nusernme = \"u\"\n").is_err());
        assert!(parse("[protect]\nhost = \"h\"\nusername = \"u\"\npassword = \"p\"\n").is_err());
    }
}
