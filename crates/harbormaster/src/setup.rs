//! `harbormaster setup`: the first run, asked as questions.
//!
//! It finds the UniFi Protect console, shows the certificate it presents
//! for the owner to confirm, signs in once to prove the account works,
//! writes `config.toml`, offers to keep the password in the Keychain and
//! installs the service. Every step can be done by hand instead; this
//! only saves editing files. Running it again changes nothing that is
//! already in place.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use harbormaster_protect::{fetch_fingerprint, Client, Error, Fingerprint};

use crate::keychain::{self, Failure};
use crate::password::Secret;
use crate::{client, config, daemon, service, tty, video};

/// How the questions are asked, so that tests can answer them.
pub trait Prompter {
    /// One line of text. An empty answer takes the default, if there is one.
    fn line(&mut self, prompt: &str, default: Option<&str>) -> Result<String>;
    /// Yes or no. An empty answer takes the default.
    fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool>;
    /// A password, typed unseen.
    fn secret(&mut self, prompt: &str) -> Result<Secret>;
}

struct Terminal;

impl Terminal {
    fn read(prompt: &str) -> Result<String> {
        print!("{prompt}");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        if std::io::stdin().lock().read_line(&mut answer)? == 0 {
            bail!("setup needs someone to answer its questions; run it in a terminal");
        }
        Ok(answer.trim().to_owned())
    }
}

impl Prompter for Terminal {
    fn line(&mut self, prompt: &str, default: Option<&str>) -> Result<String> {
        loop {
            let answer = Self::read(&match default {
                Some(default) => format!("{prompt} [{default}]: "),
                None => format!("{prompt}: "),
            })?;
            match (answer.is_empty(), default) {
                (false, _) => return Ok(answer),
                (true, Some(default)) => return Ok(default.to_owned()),
                (true, None) => {}
            }
        }
    }

    fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool> {
        loop {
            let answer = Self::read(&format!("{prompt} [{}]: ", if default { "Y/n" } else { "y/N" }))?;
            match answer.to_lowercase().as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => {}
            }
        }
    }

    fn secret(&mut self, prompt: &str) -> Result<Secret> {
        tty::read_password(prompt)
    }
}

/// The console's address as typed, tidied: people paste web addresses.
/// Returns the host and a port if one was given.
fn console_address(typed: &str) -> Option<(String, Option<u16>)> {
    let text = typed.trim();
    let text = text.strip_prefix("https://").or_else(|| text.strip_prefix("http://")).unwrap_or(text);
    let text = text.split('/').next().unwrap_or(text);
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
        None => (text, None),
    };
    let plain = |c: char| c.is_ascii_alphanumeric() || ".-".contains(c);
    (!host.is_empty() && host.chars().all(plain)).then(|| (host.to_owned(), port))
}

/// A string as TOML writes it.
fn quoted(text: &str) -> String {
    toml::Value::String(text.to_owned()).to_string()
}

/// The `[protect]` section for a console that has none yet.
fn protect_section(host: &str, port: Option<u16>, username: &str, fingerprint: &Fingerprint) -> String {
    let port = port.filter(|port| *port != 443).map_or(String::new(), |port| format!("port = {port}\n"));
    format!(
        "[protect]\nhost = {}\n{port}username = {}\nfingerprint = {}\n",
        quoted(host),
        quoted(username),
        quoted(&fingerprint.to_string())
    )
}

/// `existing` with a fingerprint added to its `[protect]` section, which
/// has none. Everything else in the file is kept as it is.
fn with_fingerprint(existing: &str, fingerprint: &Fingerprint) -> Option<String> {
    let header = existing.lines().position(|line| line.trim() == "[protect]")?;
    let mut lines: Vec<String> = existing.lines().map(str::to_owned).collect();
    lines.insert(header + 1, format!("fingerprint = {}", quoted(&fingerprint.to_string())));
    Some(lines.join("\n") + "\n")
}

/// Replaces the config file in one step with one only its owner can read.
fn write_config(state_dir: &Path, text: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    // Never write a file the daemon would then refuse to start on.
    config::parse(text).context("the new config.toml would not be valid")?;
    let path = config::path(state_dir);
    let fresh = path.with_extension("toml.new");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&fresh)
        .with_context(|| format!("writing {}", fresh.display()))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&fresh, &path).with_context(|| format!("moving {} into place", path.display()))
}

/// What setup has learned about the console.
struct Console {
    host: String,
    port: u16,
    username: String,
    pin: Fingerprint,
    /// The text `config.toml` should have, if it is to change.
    config: Option<String>,
}

/// Asks where the console is and whose certificate it shows, or takes
/// both from a config that already says.
async fn find_console(state_dir: &Path, ask: &mut dyn Prompter) -> Result<Console> {
    let path = config::path(state_dir);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let configured = config::load(state_dir)?.protect;
    let (host, port, username) = match &configured {
        Some(protect) => {
            crate::account_lines::already_configured(&path, &protect.host, &protect.username);
            (protect.host.clone(), Some(protect.port), protect.username.clone())
        }
        None => {
            println!(
                "Harbormaster signs in to UniFi Protect with an account of its own. Create one in UniFi OS\n\
                 under Admins & Users: a local-access-only admin with access to Protect. Full management\n\
                 lets Harbormaster switch floodlights; view only is enough for everything else.\n"
            );
            let (host, port) = loop {
                let typed = ask.line("Address of the console running UniFi Protect", None)?;
                match console_address(&typed) {
                    Some(address) => break address,
                    None => println!("That does not look like an address. An IP address such as 192.168.1.1 is what is wanted."),
                }
            };
            (host, port, ask.line("Username of that account", Some("harbormaster"))?)
        }
    };
    let port_number = port.unwrap_or(443);

    if let Some(pinned) = configured.as_ref().and_then(|protect| protect.fingerprint.as_ref()) {
        let pin = pinned.parse().context("fingerprint in config.toml")?;
        return Ok(Console { host, port: port_number, username, pin, config: None });
    }
    let seen = fetch_fingerprint(&host, port_number)
        .await
        .with_context(|| format!("connecting to {host}:{port_number}"))?;
    println!(
        "\nThe console at {host} presents a certificate with this fingerprint:\n\n    {seen}\n\n\
         Harbormaster will only ever talk to a console that presents exactly this certificate.\n\
         Nothing has been sent to it yet."
    );
    if !ask.confirm("Is that your console?", true)? {
        bail!("nothing was changed");
    }
    let config = match &configured {
        Some(_) => with_fingerprint(&existing, &seen).context("could not find [protect] in config.toml to add the fingerprint to")?,
        None => {
            let gap = if existing.is_empty() || existing.ends_with("\n\n") { "" } else { "\n" };
            format!("{existing}{gap}{}", protect_section(&host, port, &username, &seen))
        }
    };
    Ok(Console { host, port: port_number, username, pin: seen, config: Some(config) })
}

/// Signs in once to prove the account works. Returns the password that
/// did, and whether it came from the Keychain.
async fn sign_in(console: &Console, ask: &mut dyn Prompter) -> Result<(Secret, bool)> {
    let stored = if cfg!(target_os = "macos") {
        keychain::lookup(keychain::PROTECT_SERVICE, &console.username, Some(std::time::Duration::from_secs(5))).ok()
    } else {
        None
    };
    let mut candidate = stored;
    let mut from_keychain = candidate.is_some();
    for _ in 0..3 {
        let password = match candidate.take() {
            Some(password) => {
                println!("Using the password already in the Keychain.");
                password
            }
            None => {
                from_keychain = false;
                let typed = ask.secret(&format!("Password for \"{}\": ", console.username))?;
                if typed.is_empty() {
                    bail!("no password was entered; nothing was changed");
                }
                typed
            }
        };
        let mut client = Client::new(&console.host, console.port, console.pin);
        match client.login(&console.username, password.expose()).await {
            Ok(()) => {
                let found = client.bootstrap().await?;
                println!(
                    "Signed in to {} ({}), Protect {}: {} cameras, {} lights, {} sensors.",
                    found.nvr.name.as_deref().unwrap_or("the console"),
                    found.nvr.model,
                    found.nvr.version,
                    found.cameras.len(),
                    found.lights.len(),
                    found.sensors.len()
                );
                return Ok((password, from_keychain));
            }
            Err(Error::BadCredentials) => println!("The console rejected that username or password."),
            Err(other) => return Err(other).context("signing in to UniFi Protect"),
        }
    }
    bail!("the console rejected the password three times; nothing was changed")
}

/// Offers to keep the password in the Keychain, where `harbormaster
/// unlock` finds it.
fn keep_password(username: &str, password: &Secret, ask: &mut dyn Prompter) -> Result<()> {
    if !cfg!(target_os = "macos") {
        println!("There is no password store on this system yet, so `harbormaster unlock` will ask for the password.");
        return Ok(());
    }
    if !ask.confirm("Keep the password in your login Keychain, so that it need not be typed again?", true)? {
        println!("`harbormaster unlock` will ask for it instead.");
        return Ok(());
    }
    let mut outcome = keychain::store(keychain::PROTECT_SERVICE, username, password);
    if matches!(outcome, Err(Failure::Locked(_))) {
        println!("The Keychain is locked. macOS will now ask for your Mac login password to unlock it.");
        keychain::unlock_interactively()?;
        outcome = keychain::store(keychain::PROTECT_SERVICE, username, password);
        keychain::lock();
    }
    match outcome {
        Ok(()) => println!("Stored in the Keychain."),
        Err(why) => crate::account_lines::could_not_store(
            &why,
            &keychain::store_command(keychain::PROTECT_SERVICE, username),
        ),
    }
    Ok(())
}

/// Hands the password to a daemon that is waiting for it, if one is.
fn hand_over(state_dir: &Path, password: Secret) {
    let waiting = client::state(state_dir)
        .is_ok_and(|state| state.console.is_some_and(|console| console.waiting_for_password));
    if !waiting {
        return;
    }
    match client::unlock(state_dir, password) {
        Ok(reply) if reply.signed_in => println!("The service is signed in. {} devices are published to HomeKit.", reply.devices),
        Ok(reply) if reply.kept => println!("The service has the password and is still connecting ({}).", reply.detail),
        Ok(reply) => println!("The service could not sign in: {}", reply.detail),
        Err(why) => println!("The password could not be handed to the service: {why:#}"),
    }
}

/// Bold where the output is a terminal, plain where it is a file or a pipe.
fn bold(text: &str) -> String {
    if std::io::stdout().is_terminal() {
        format!("\x1b[1m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// What setup opens with: whose questions these are, and how many.
fn banner() -> String {
    format!(
        "\n  {}\n  HomeKit bridge for UniFi Protect\n\n  \
         Setup is four steps: find your console, sign in, run as a service, add to Home.\n  \
         It is safe to run again; nothing already in place is changed.\n",
        bold(&format!("\u{2693} Harbormaster {}", env!("CARGO_PKG_VERSION")))
    )
}

fn step(number: u8, title: &str) -> String {
    bold(&format!("Step {number} of 4  {title}"))
}

/// The pairing code of a running, unpaired bridge, drawn for the Home
/// app to scan. Nothing when the service is not up or is already paired.
fn pairing_code(state_dir: &Path) -> Option<String> {
    let state = client::state(state_dir).ok()?;
    let code = state.setup_code?;
    let picture = state.setup_uri.as_deref().and_then(crate::qr::render).map(|qr| format!("{qr}\n\n")).unwrap_or_default();
    Some(format!("{picture}Setup code: {code}"))
}

pub fn run(state_dir: &Path, user_agent: bool) -> Result<()> {
    let ask: &mut dyn Prompter = &mut Terminal;
    println!("{}", banner());
    daemon::create_private_dir(state_dir)?;
    let runtime = tokio::runtime::Runtime::new()?;

    println!("{}\n", step(1, "The UniFi Protect console"));
    let console = runtime.block_on(find_console(state_dir, ask))?;

    println!("\n{}\n", step(2, "Signing in"));
    let (password, from_keychain) = runtime.block_on(sign_in(&console, ask))?;
    if let Some(text) = &console.config {
        write_config(state_dir, text)?;
        println!("Wrote {}.", config::path(state_dir).display());
    }
    if !from_keychain {
        keep_password(&console.username, &password, ask)?;
    }
    if video::find_ffmpeg().is_none() {
        println!("\nLive video and recording need ffmpeg, which was not found. With Homebrew: brew install ffmpeg");
    }

    println!("\n{}\n", step(3, "Running as a service"));
    // A daemon started before the console was configured does not know of it.
    let stale = console.config.is_some() && client::state(state_dir).is_ok();
    if ask.confirm("Install Harbormaster as a service that starts at boot and is restarted if it stops?", true)? {
        let options = service::Options {
            scope: if user_agent { service::Scope::User } else { service::Scope::System },
            listen: None,
            demo: false,
        };
        service::install(state_dir, &options)?;
        if stale {
            println!("The running daemon was started before this configuration. Restart it:\n\n    harbormaster service restart\n");
        } else {
            hand_over(state_dir, password);
        }
    } else {
        println!("To run it yourself: harbormaster daemon");
    }

    println!("\n{}\n", step(4, "Adding it to Home"));
    match pairing_code(state_dir) {
        Some(code) => println!(
            "In the Home app choose Add Accessory, then scan this code or type it in.\n\n{code}\n\n\
             The dashboard shows it again until the bridge is paired: harbormaster"
        ),
        None => println!(
            "Once the service is running and has the password (`harbormaster unlock`), open the dashboard\n\
             with `harbormaster`: it shows the pairing code. In the Home app choose Add Accessory and scan\n\
             it, or choose More Options and pick Harbormaster."
        ),
    }
    if cfg!(target_os = "macos") {
        println!(
            "\nIf the service cannot reach the console (\"No route to host\"), allow it under System Settings,\n\
             Privacy & Security, Local Network. macOS asks for this once."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pasted_addresses_are_tidied_and_nonsense_refused() {
        let address = |typed: &str| console_address(typed);
        assert_eq!(address(" 192.0.2.10 "), Some(("192.0.2.10".into(), None)));
        assert_eq!(address("https://unvr.example/protect/dashboard"), Some(("unvr.example".into(), None)));
        assert_eq!(address("192.0.2.10:8443"), Some(("192.0.2.10".into(), Some(8443))));
        for bad in ["", "   ", "my console", "host:port", "a\"b"] {
            assert_eq!(address(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_opening_names_the_program_and_the_steps_are_numbered() {
        let banner = banner();
        assert!(banner.contains(&format!("Harbormaster {}", env!("CARGO_PKG_VERSION"))), "{banner}");
        assert!(banner.contains("HomeKit bridge for UniFi Protect") && banner.contains("four steps"));
        // Tests do not run on a terminal, so nothing is styled.
        assert_eq!(step(2, "Signing in"), "Step 2 of 4  Signing in");
        assert_eq!(pairing_code(Path::new("/nonexistent/harbormaster")), None);
    }

    fn pin() -> Fingerprint {
        Fingerprint::of(b"a certificate")
    }

    #[test]
    fn a_new_section_is_valid_and_keeps_what_was_there() {
        let section = protect_section("192.0.2.10", None, "harbor\"master", &pin());
        let protect = config::parse(&section).unwrap().protect.unwrap();
        assert_eq!((protect.host.as_str(), protect.port, protect.username.as_str()), ("192.0.2.10", 443, "harbor\"master"));
        assert_eq!(protect.fingerprint.unwrap().parse::<Fingerprint>().unwrap(), pin());
        let odd_port = protect_section("h", Some(8443), "u", &pin());
        assert_eq!(config::parse(&odd_port).unwrap().protect.unwrap().port, 8443);
        assert!(!protect_section("h", Some(443), "u", &pin()).contains("port"));
    }

    #[test]
    fn a_fingerprint_is_added_without_disturbing_the_rest() {
        let existing = "# mine\n[protect]\nhost = \"h\"\nusername = \"u\"\nname_prefix = \"HM \"\n";
        let text = with_fingerprint(existing, &pin()).unwrap();
        assert!(text.starts_with("# mine\n[protect]\nfingerprint = \""), "{text}");
        let protect = config::parse(&text).unwrap().protect.unwrap();
        assert_eq!((protect.name_prefix.as_str(), protect.fingerprint.is_some()), ("HM ", true));
        assert_eq!(with_fingerprint("nothing here\n", &pin()), None);
    }

    #[test]
    fn the_config_is_written_private_and_never_invalid() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("hm-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(write_config(&dir, "[protect]\nhost = 3\n").is_err());
        assert!(!config::path(&dir).exists(), "a bad file is never put in place");
        write_config(&dir, &protect_section("192.0.2.10", None, "u", &pin())).unwrap();
        assert_eq!(std::fs::metadata(config::path(&dir)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(config::load(&dir).unwrap().protect.unwrap().host, "192.0.2.10");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
