//! Harbormaster: a HomeKit bridge with a terminal interface.
//!
//! `harbormaster daemon` runs the bridge. `harbormaster` (or `harbormaster
//! tui`) attaches a terminal interface to a running daemon.

mod config;
mod control;
mod daemon;
mod fmp4;
mod keychain;
mod logbuf;
mod protect_bridge;
mod protect_check;
mod qr;
mod recording;
mod secrets;
mod tui;
mod video;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const HELP: &str = "\
Usage: harbormaster [COMMAND] [OPTIONS]

Commands:
  tui      attach the terminal interface to a running daemon (default)
  daemon   run the HomeKit bridge
  protect-check
           test the UniFi Protect connection and list its cameras
  protect-capture
           record Protect's inventory and live updates to files for development
  protect-feed
           record a few seconds of a camera's native live feed for development

Options:
  --state-dir DIR   where config.toml, pairing state and the control socket live
  --listen ADDR     daemon: address and port to serve HomeKit on
                    (default 0.0.0.0:51826, which serves IPv4 and IPv6)
  --demo            daemon: publish a simulated temperature sensor
  --seconds N       protect-capture, protect-feed: how long to record (default 120)
  --camera NAME     protect-feed: which camera (default: the first in `devices`)
  --channel N       protect-feed: which quality, 0 being the best (default 0)";

enum Command {
    Tui,
    Daemon,
    ProtectCheck,
    ProtectCapture,
    ProtectFeed,
}

struct Args {
    command: Command,
    state_dir: PathBuf,
    listen: SocketAddr,
    demo: bool,
    seconds: u64,
    camera: Option<String>,
    channel: u8,
}

fn default_state_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set; pass --state-dir")?;
    Ok(PathBuf::from(home).join("Library/Application Support/harbormaster"))
}

fn parse_args(input: impl IntoIterator<Item = String>) -> Result<Args> {
    let mut args = Args {
        command: Command::Tui,
        state_dir: PathBuf::new(),
        listen: "0.0.0.0:51826".parse()?,
        demo: false,
        seconds: 120,
        camera: None,
        channel: 0,
    };
    let mut input = input.into_iter();
    while let Some(arg) = input.next() {
        let mut value = || input.next().with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "tui" => args.command = Command::Tui,
            "daemon" => args.command = Command::Daemon,
            "protect-check" => args.command = Command::ProtectCheck,
            "protect-capture" => args.command = Command::ProtectCapture,
            "protect-feed" => args.command = Command::ProtectFeed,
            "--camera" => args.camera = Some(value()?),
            "--channel" => args.channel = value()?.parse().context("--channel expects a small number")?,
            "--seconds" => args.seconds = value()?.parse().context("--seconds expects a number")?,
            "--state-dir" => args.state_dir = value()?.into(),
            "--listen" => args.listen = value()?.parse().context("--listen expects ADDRESS:PORT")?,
            "--demo" => args.demo = true,
            "--help" | "-h" => {
                println!("harbormaster {}\n\n{HELP}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}; try --help"),
        }
    }
    if args.state_dir.as_os_str().is_empty() {
        args.state_dir = default_state_dir()?;
    }
    Ok(args)
}

fn main() -> Result<()> {
    let args = parse_args(std::env::args().skip(1))?;
    match args.command {
        Command::Tui => tui::run(&args.state_dir),
        Command::ProtectCheck => {
            tokio::runtime::Runtime::new()?.block_on(protect_check::run(&args.state_dir))
        }
        Command::ProtectCapture => {
            tokio::runtime::Runtime::new()?.block_on(protect_check::capture(&args.state_dir, args.seconds))
        }
        Command::ProtectFeed => tokio::runtime::Runtime::new()?.block_on(protect_check::feed(
            &args.state_dir,
            args.camera.as_deref(),
            args.channel,
            args.seconds,
        )),
        Command::Daemon => {
            let logs = logbuf::LogBuffer::new();
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                .with(tracing_subscriber::filter::LevelFilter::INFO)
                .with(logs.clone())
                .init();
            let options =
                daemon::Options { state_dir: args.state_dir, listen: args.listen, demo: args.demo };
            tokio::runtime::Runtime::new()?.block_on(daemon::run(options, logs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_commands_and_options() {
        let args = parse(&["daemon", "--demo", "--state-dir", "/x", "--listen", "127.0.0.1:1"]).unwrap();
        assert!(matches!(args.command, Command::Daemon) && args.demo);
        assert_eq!((args.state_dir, args.listen.port()), (PathBuf::from("/x"), 1));
        assert!(matches!(parse(&["--state-dir", "/x"]).unwrap().command, Command::Tui));
        let feed = parse(&["protect-feed", "--camera", "Front Door", "--channel", "1", "--seconds", "5"]).unwrap();
        assert!(matches!(feed.command, Command::ProtectFeed));
        assert_eq!((feed.camera.as_deref(), feed.channel, feed.seconds), (Some("Front Door"), 1, 5));
        assert!(parse(&["bogus"]).is_err());
        assert!(parse(&["--listen"]).is_err());
    }
}
