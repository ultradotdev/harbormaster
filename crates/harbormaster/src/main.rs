//! Harbormaster: a HomeKit bridge with a terminal interface.
//!
//! `harbormaster daemon` runs the bridge. `harbormaster` (or `harbormaster
//! tui`) attaches a terminal interface to a running daemon.

mod account_lines;
mod client;
mod clock;
mod config;
mod control;
mod daemon;
mod demo;
mod fmp4;
mod keychain;
mod launchd;
mod logbuf;
mod logfile;
#[cfg(feature = "mock-console")]
mod mock_console;
mod overrides;
mod password;
mod protect_bridge;
mod protect_check;
mod qr;
mod recording;
mod secrets;
mod service;
mod setup;
mod status;
#[cfg(test)]
mod test_random;
mod tty;
mod tui;
mod unlock;
mod video;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const HELP: &str = "\
Usage: harbormaster [COMMAND] [OPTIONS]

Commands:
  setup    first run: find the UniFi Protect console, sign in, write the
           configuration and install the service, asking as it goes
  tui      attach the terminal interface to a running daemon (default)
  daemon   run the HomeKit bridge
  unlock   give the running daemon the UniFi Protect password. It is read
           from the Keychain (unlocking it if need be) or asked for here
  service install | uninstall | status | restart | stop | start
           run the daemon as a service that starts at boot and is restarted
           if it stops, remove that service, say what is running, restart
           it, or stop it until it is started again
  logs     print the end of the daemon's log; --follow keeps printing
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
  --demo            daemon: publish simulated devices, to try the dashboard
                    without a UniFi Protect console
  --verbose         daemon: also log each event sent to a controller
  --detached        daemon: log to the file in the state directory only, not
                    to the terminal as well (the installed service uses this)
  --version         print the version
  --user-agent      service, setup: a per-user agent, which needs no sudo but only
                    runs while you are logged in at the screen. The default
                    is a system service that runs as you from boot
  --stdin           unlock: read the password from standard input instead
  --follow, -f      logs: keep printing new lines until interrupted
  --lines N, -n N   logs: how many lines to print first (default 40)
  --seconds N       protect-capture, protect-feed: how long to record (default 120)
  --camera NAME     protect-feed: which camera (default: the first in `devices`)
  --channel N       protect-feed: which quality, 0 being the best (default 0)
  --lens N          protect-feed: which lens of a multi-lens camera (default 0)";

enum Command {
    Setup,
    Tui,
    Daemon,
    Unlock,
    ServiceInstall,
    ServiceUninstall,
    ServiceStatus,
    ServiceRestart,
    ServiceStop,
    ServiceStart,
    Logs,
    ProtectCheck,
    ProtectCapture,
    ProtectFeed,
    /// A pretend console for testing. Only builds made with the
    /// `mock-console` feature have it, so it is left out of the help.
    MockConsole,
}

struct Args {
    command: Command,
    state_dir: PathBuf,
    listen: SocketAddr,
    demo: bool,
    verbose: bool,
    detached: bool,
    user_agent: bool,
    /// Whether --listen was given, rather than left at its default.
    listen_given: bool,
    stdin: bool,
    follow: bool,
    lines: usize,
    seconds: u64,
    camera: Option<String>,
    channel: u8,
    lens: u8,
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
        verbose: false,
        detached: false,
        user_agent: false,
        listen_given: false,
        stdin: false,
        follow: false,
        lines: 40,
        seconds: 120,
        camera: None,
        channel: 0,
        lens: 0,
    };
    let mut input = input.into_iter();
    while let Some(arg) = input.next() {
        let mut value = || input.next().with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "setup" => args.command = Command::Setup,
            "tui" => args.command = Command::Tui,
            "daemon" => args.command = Command::Daemon,
            "unlock" => args.command = Command::Unlock,
            "service" => {
                args.command = match input.next().as_deref() {
                    Some("install") => Command::ServiceInstall,
                    Some("uninstall") => Command::ServiceUninstall,
                    Some("status") => Command::ServiceStatus,
                    Some("restart") => Command::ServiceRestart,
                    Some("stop") => Command::ServiceStop,
                    Some("start") => Command::ServiceStart,
                    _ => bail!("service needs one of: install, uninstall, status, restart, stop, start"),
                }
            }
            "logs" => args.command = Command::Logs,
            "--follow" | "-f" => args.follow = true,
            "--lines" | "-n" => args.lines = value()?.parse().context("--lines expects a number")?,
            "--user-agent" => args.user_agent = true,
            "protect-check" => args.command = Command::ProtectCheck,
            "protect-capture" => args.command = Command::ProtectCapture,
            "protect-feed" => args.command = Command::ProtectFeed,
            "mock-console" => args.command = Command::MockConsole,
            "--camera" => args.camera = Some(value()?),
            "--lens" => args.lens = value()?.parse().context("--lens expects a small number")?,
            "--channel" => args.channel = value()?.parse().context("--channel expects a small number")?,
            "--seconds" => args.seconds = value()?.parse().context("--seconds expects a number")?,
            "--state-dir" => args.state_dir = value()?.into(),
            "--listen" => {
                args.listen = value()?.parse().context("--listen expects ADDRESS:PORT")?;
                args.listen_given = true;
            }
            "--demo" => args.demo = true,
            "--verbose" => args.verbose = true,
            "--stdin" => args.stdin = true,
            "--detached" => args.detached = true,
            "--version" | "-V" => {
                println!("harbormaster {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
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

/// Commands that look at an installation say so plainly when there is
/// none, rather than failing on whichever file they reach for first.
fn require_setup(args: &Args) -> Result<()> {
    let looks = matches!(
        args.command,
        Command::Tui
            | Command::Unlock
            | Command::Logs
            | Command::ServiceStatus
            | Command::ServiceRestart
            | Command::ServiceStop
            | Command::ServiceStart
            | Command::ServiceUninstall
    );
    if looks && !args.state_dir.exists() {
        bail!(
            "Harbormaster is not set up yet (there is no {}). Start with:\n\n    harbormaster setup\n",
            args.state_dir.display()
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = parse_args(std::env::args().skip(1))?;
    require_setup(&args)?;
    match args.command {
        Command::Setup => setup::run(&args.state_dir, args.user_agent),
        Command::Tui => tui::run(&args.state_dir),
        Command::Unlock => unlock::run(&args.state_dir, args.stdin),
        Command::Logs => logfile::show(&args.state_dir, args.lines, args.follow),
        Command::ServiceRestart => service::restart(&args.state_dir),
        Command::ServiceStop => service::stop(&args.state_dir),
        Command::ServiceStart => service::start(&args.state_dir),
        Command::ServiceInstall | Command::ServiceUninstall | Command::ServiceStatus => {
            let options = service::Options {
                scope: if args.user_agent { service::Scope::User } else { service::Scope::System },
                listen: args.listen_given.then_some(args.listen),
                demo: args.demo,
            };
            match args.command {
                Command::ServiceInstall => service::install(&args.state_dir, &options),
                Command::ServiceUninstall => service::uninstall(&args.state_dir, &options),
                _ => service::status(&args.state_dir),
            }
        }
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
            args.lens,
            args.seconds,
        )),
        #[cfg(feature = "mock-console")]
        Command::MockConsole => {
            let listen = if args.listen_given { args.listen } else { mock_console::DEFAULT_LISTEN.parse()? };
            mock_console::run(&args.state_dir, listen, args.stdin)
        }
        #[cfg(not(feature = "mock-console"))]
        Command::MockConsole => bail!(
            "this build has no mock console: it is a testing aid, left out of releases. \
             Build from source with `cargo build --features mock-console` to get it"
        ),
        Command::Daemon => {
            let logs = logbuf::LogBuffer::new();
            // The log file lives in the state directory, which holds
            // pairing keys and is the owner's alone.
            daemon::create_private_dir(&args.state_dir)?;
            if args.detached {
                service::trim_output(&args.state_dir);
            }
            // In the foreground the terminal gets every line as well. A
            // detached daemon's stderr is a file nothing rotates, so only
            // what cannot go through the log (a panic, a failed start)
            // ends up there.
            let stderr = (!args.detached).then(|| tracing_subscriber::fmt::layer().with_writer(std::io::stderr));
            tracing_subscriber::registry()
                .with(stderr)
                .with(logfile::LogFile::open(&args.state_dir)?)
                .with(if args.verbose {
                    tracing_subscriber::filter::LevelFilter::DEBUG
                } else {
                    tracing_subscriber::filter::LevelFilter::INFO
                })
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
        let install = parse(&["service", "install", "--user-agent", "--demo"]).unwrap();
        assert!(matches!(install.command, Command::ServiceInstall) && install.user_agent && !install.listen_given);
        assert!(matches!(parse(&["service", "status"]).unwrap().command, Command::ServiceStatus));
        assert!(matches!(parse(&["service", "restart"]).unwrap().command, Command::ServiceRestart));
        assert!(matches!(parse(&["service", "stop"]).unwrap().command, Command::ServiceStop));
        assert!(matches!(parse(&["service", "start"]).unwrap().command, Command::ServiceStart));
        assert!(parse(&["service"]).is_err() && parse(&["service", "bounce"]).is_err());
        let logs = parse(&["logs", "-f", "-n", "5"]).unwrap();
        assert!(matches!(logs.command, Command::Logs) && logs.follow && logs.lines == 5);
        assert!(!parse(&["logs"]).unwrap().follow && parse(&["logs", "--lines", "x"]).is_err());
        let detached = parse(&["daemon", "--detached", "--listen", "127.0.0.1:1"]).unwrap();
        assert!(detached.detached && detached.listen_given);
        assert!(matches!(parse(&["unlock", "--stdin"]).unwrap(), Args { command: Command::Unlock, stdin: true, .. }));
        assert!(parse(&["bogus"]).is_err());
        // Looking at an installation that is not there is one plain message.
        for looking in [&["service", "status"][..], &["logs"], &["unlock"], &["tui"], &[]] {
            let mut words = looking.to_vec();
            words.extend(["--state-dir", "/nonexistent/harbormaster"]);
            let said = require_setup(&parse(&words).unwrap()).unwrap_err().to_string();
            assert!(said.contains("not set up yet") && said.contains("harbormaster setup"), "{said}");
        }
        for making in [&["setup"][..], &["daemon"], &["service", "install"]] {
            let mut words = making.to_vec();
            words.extend(["--state-dir", "/nonexistent/harbormaster"]);
            assert!(require_setup(&parse(&words).unwrap()).is_ok());
        }
        assert!(parse(&["--listen"]).is_err());
    }
}
