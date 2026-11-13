//! `harbormaster service install | uninstall | status`: running the daemon
//! detached, started by the system and restarted if it stops.
//!
//! What a service file looks like and how it is loaded belongs to the
//! system's service manager and sits behind `Manager`. launchd is the one
//! implemented; a systemd unit would be a second implementation and
//! nothing else here would change.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::{client, control, daemon};

/// The service's name to the service manager.
pub const LABEL: &str = "dev.ultra.harbormaster";

/// Whatever the daemon writes outside its log: a panic, a failed start.
pub const OUTPUT_NAME: &str = "service.out";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Started at boot, with nobody logged in, as the owner.
    System,
    /// Started when the owner logs in at the screen.
    User,
}

/// Everything a service file is made from. There is no secret among it.
#[derive(Clone, Debug)]
pub struct Spec {
    pub label: String,
    pub scope: Scope,
    /// The installed binary the service runs.
    pub program: PathBuf,
    pub state_dir: PathBuf,
    /// The owner, whom the daemon runs as.
    pub user: String,
    pub uid: u32,
    pub home: PathBuf,
    /// Passed on to the daemon when given.
    pub listen: Option<SocketAddr>,
    pub demo: bool,
}

impl Spec {
    /// The daemon's command line.
    pub fn arguments(&self) -> Vec<String> {
        let mut arguments = vec![
            self.program.to_string_lossy().into_owned(),
            "daemon".to_owned(),
            "--detached".to_owned(),
            "--state-dir".to_owned(),
            self.state_dir.to_string_lossy().into_owned(),
        ];
        if let Some(listen) = self.listen {
            arguments.extend(["--listen".to_owned(), listen.to_string()]);
        }
        if self.demo {
            arguments.push("--demo".to_owned());
        }
        arguments
    }

    pub fn output(&self) -> PathBuf {
        self.state_dir.join(OUTPUT_NAME)
    }
}

/// One command of an installation, which is either run here or, when it
/// needs administrator rights, printed for the owner to run.
#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    argv: Vec<String>,
    /// The service manager may need a moment before this succeeds.
    retry: bool,
}

impl Step {
    pub fn new<const N: usize>(argv: [&str; N]) -> Self {
        Self { argv: argv.iter().map(|a| (*a).to_owned()).collect(), retry: false }
    }

    pub fn path(mut self, path: &Path) -> Self {
        self.argv.push(path.to_string_lossy().into_owned());
        self
    }

    pub fn retried(mut self) -> Self {
        self.retry = true;
        self
    }

    /// The command as it would be typed into a shell.
    pub fn shell(&self) -> String {
        self.argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
    }

    fn run(&self) -> Result<()> {
        let attempts = if self.retry { 10 } else { 1 };
        let mut last = String::new();
        for attempt in 0..attempts {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(500));
            }
            let output = std::process::Command::new(&self.argv[0])
                .args(&self.argv[1..])
                .stdin(std::process::Stdio::null())
                .output()
                .with_context(|| format!("running {}", self.argv[0]))?;
            if output.status.success() {
                return Ok(());
            }
            last = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        }
        bail!("`{}` failed: {last}", self.shell())
    }
}

/// Quotes an argument for a POSIX shell, if it needs it.
fn quote(argument: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-=:,+@".contains(c);
    if !argument.is_empty() && argument.chars().all(plain) {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

/// A system's service manager.
pub trait Manager {
    /// Where the service file must be for the system to use it.
    fn unit_path(&self, spec: &Spec) -> PathBuf;
    /// The service file's contents.
    fn unit(&self, spec: &Spec) -> String;
    /// Whether putting the file in place and loading it takes root.
    fn needs_root(&self, spec: &Spec) -> bool;
    /// The commands that load the service, replacing a loaded one. When
    /// root is needed they also copy the file from `staged` into place.
    fn load_steps(&self, spec: &Spec, staged: &Path, loaded: bool) -> Vec<Step>;
    /// The commands that stop the service and remove its file.
    fn unload_steps(&self, spec: &Spec, loaded: bool) -> Vec<Step>;
    /// The commands that stop the service until it is started again or
    /// the machine restarts, leaving its file in place.
    fn stop_steps(&self, spec: &Spec) -> Vec<Step>;
    /// The commands that start a stopped service from its file.
    fn start_steps(&self, spec: &Spec) -> Vec<Step>;
    /// What the system says about the service, if it knows of it.
    fn loaded(&self, spec: &Spec) -> Option<String>;
}

fn manager() -> Result<Box<dyn Manager>> {
    if cfg!(target_os = "macos") {
        Ok(Box::new(crate::launchd::Launchd))
    } else {
        bail!(
            "installing Harbormaster as a service is only done for macOS so far. On another system, have its \
             service manager run `harbormaster daemon --detached --state-dir DIR` as your user"
        )
    }
}

pub struct Options {
    pub scope: Scope,
    pub listen: Option<SocketAddr>,
    pub demo: bool,
}

/// Who is running this command, and so who the service will run as.
fn owner() -> Result<(String, u32, PathBuf)> {
    // SAFETY: geteuid cannot fail, and getpwuid's result is copied out
    // before anything else could overwrite its static buffer.
    let (uid, name, directory) = unsafe {
        let uid = libc::geteuid();
        let entry = libc::getpwuid(uid);
        if entry.is_null() {
            bail!("cannot tell which user this is (uid {uid})");
        }
        let text = |pointer| std::ffi::CStr::from_ptr(pointer).to_string_lossy().into_owned();
        (uid, text((*entry).pw_name), text((*entry).pw_dir))
    };
    if uid == 0 {
        bail!(
            "run this as the user the bridge should run as, without sudo. \
             The one step that needs administrator rights is printed for you to run"
        );
    }
    let home = std::env::var_os("HOME").map_or(PathBuf::from(directory), PathBuf::from);
    Ok((name, uid, home))
}

fn spec(state_dir: &Path, options: &Options) -> Result<Spec> {
    let (user, uid, home) = owner()?;
    // The service manager needs the real path, wherever this was run from.
    let state_dir = std::fs::canonicalize(state_dir).with_context(|| format!("finding {}", state_dir.display()))?;
    Ok(Spec {
        label: LABEL.to_owned(),
        scope: options.scope,
        program: installed_binary(&state_dir),
        state_dir,
        user,
        uid,
        home,
        listen: options.listen,
        demo: options.demo,
    })
}

/// Where the service's own copy of the binary lives.
fn installed_binary(state_dir: &Path) -> PathBuf {
    state_dir.join("bin").join("harbormaster")
}

/// Puts a copy of `source` at `destination`. Returns whether anything
/// changed. A binary that is running is never written over: on Apple
/// silicon that invalidates its signature and macOS kills every launch
/// from then on. The copy is made beside it and renamed into place, which
/// leaves the running process its old file.
fn install_binary(source: &Path, destination: &Path) -> Result<bool> {
    let wanted = std::fs::read(source).with_context(|| format!("reading {}", source.display()))?;
    if std::fs::read(destination).is_ok_and(|present| present == wanted) {
        return Ok(false);
    }
    let directory = destination.parent().context("the binary's destination has no directory")?;
    std::fs::create_dir_all(directory).with_context(|| format!("creating {}", directory.display()))?;
    let fresh = destination.with_extension("new");
    let _ = std::fs::remove_file(&fresh);
    // `copy` keeps the mode, and on macOS the code signature with it.
    std::fs::copy(source, &fresh).with_context(|| format!("copying to {}", fresh.display()))?;
    std::fs::rename(&fresh, destination).with_context(|| format!("moving {} into place", destination.display()))?;
    Ok(true)
}

/// Writes a file by way of a temporary one, so it is never half there.
fn write_atomically(path: &Path, contents: &str) -> Result<()> {
    let directory = path.parent().context("the file has no directory")?;
    std::fs::create_dir_all(directory).with_context(|| format!("creating {}", directory.display()))?;
    let fresh = path.with_extension("new");
    std::fs::write(&fresh, contents).with_context(|| format!("writing {}", fresh.display()))?;
    std::fs::rename(&fresh, path).with_context(|| format!("moving {} into place", path.display()))
}

/// Makes sure the file the service's output goes to exists and is the
/// owner's alone, before the service manager can create it otherwise.
fn prepare_output(spec: &Spec) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = spec.output();
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Called by a detached daemon as it starts: nothing rotates the service's
/// output file, so one that has grown large is emptied.
pub fn trim_output(state_dir: &Path) {
    const LIMIT: u64 = 1024 * 1024;
    let path = state_dir.join(OUTPUT_NAME);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LIMIT) {
        if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&path) {
            let _ = file.set_len(0);
        }
    }
}

/// Asks the running daemon to stop, and waits until it has. launchd (or
/// whatever keeps the service) then starts the new one.
fn stop_daemon(state_dir: &Path, pid: u32) {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return };
    if pid <= 1 {
        return;
    }
    // SAFETY: kill has no memory-safety preconditions.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match client::state(state_dir) {
            Ok(state) if i64::from(state.pid) == i64::from(pid) => std::thread::sleep(Duration::from_millis(200)),
            _ => return,
        }
    }
}

/// Waits for a daemon other than `old_pid` to answer on the control socket.
fn wait_for_daemon(state_dir: &Path, old_pid: Option<u32>) -> Option<control::State> {
    // launchd waits up to its throttle interval before a restart.
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match client::state(state_dir) {
            Ok(state) if Some(state.pid) != old_pid => return Some(state),
            _ if Instant::now() >= deadline => return None,
            _ => std::thread::sleep(Duration::from_millis(300)),
        }
    }
}

/// Where a link to the installed binary goes, so that it can be run as
/// plain `harbormaster`. The directory is on the command path of every
/// login shell on macOS and most other systems.
const LINK: &str = "/usr/local/bin/harbormaster";

/// Whether `link` is a link to `program`.
fn linked(program: &Path, link: &Path) -> bool {
    std::fs::read_link(link).is_ok_and(|target| target == program)
}

/// Links `link` to `program`, replacing a link that points elsewhere but
/// never a real file. Returns whether the link is now in place.
fn link_binary(program: &Path, link: &Path) -> bool {
    if linked(program, link) {
        return true;
    }
    match std::fs::symlink_metadata(link) {
        Ok(present) if !present.file_type().is_symlink() => return false,
        Ok(_) => drop(std::fs::remove_file(link)),
        Err(_) => {}
    }
    if let Some(directory) = link.parent() {
        let _ = std::fs::create_dir_all(directory);
    }
    std::os::unix::fs::symlink(program, link).is_ok()
}

/// Whether a `harbormaster` is already on the command path without the
/// link, as it is when a package manager or the install script put it
/// there. A link at `link` itself does not count: it may be a stale one.
fn on_path_elsewhere(path: Option<&std::ffi::OsStr>, link: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let runnable = |candidate: &Path| {
        let is_link = std::fs::symlink_metadata(candidate).is_ok_and(|m| m.file_type().is_symlink());
        !(candidate == link && is_link)
            && std::fs::metadata(candidate).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    path.is_some_and(|path| std::env::split_paths(path).any(|directory| runnable(&directory.join("harbormaster"))))
}

/// Whether typing plain `harbormaster` runs this program.
fn runs_by_name(spec: &Spec) -> bool {
    let link = Path::new(LINK);
    linked(&spec.program, link) || on_path_elsewhere(std::env::var_os("PATH").as_deref(), link)
}

/// Makes the installed binary runnable as plain `harbormaster`, or says
/// how, since the directory usually belongs to the administrator.
fn offer_link(spec: &Spec) {
    let link = Path::new(LINK);
    if runs_by_name(spec) {
        return;
    }
    if link_binary(&spec.program, link) {
        println!("Linked {LINK}, so it can be run as plain `harbormaster`.");
    } else if std::fs::symlink_metadata(link).is_ok_and(|present| !present.file_type().is_symlink()) {
        println!("{LINK} is some other program, so no link was made there.");
    } else {
        println!(
            "To run it as plain `harbormaster`, link it onto the command path. That takes\n\
             administrator rights, so run these yourself:\n\n    sudo /bin/mkdir -p {}\n    sudo /bin/ln -sfn {} {LINK}\n",
            link.parent().unwrap_or(Path::new("/")).display(),
            quote(&spec.program.to_string_lossy()),
        );
    }
}

/// `harbormaster ARGS`, as the owner would type it for this installation.
fn invocation(spec: &Spec, arguments: &str) -> String {
    let default = crate::default_state_dir().ok().and_then(|dir| std::fs::canonicalize(dir).ok());
    let state_dir = if default.as_deref() == Some(spec.state_dir.as_path()) {
        String::new()
    } else {
        format!(" --state-dir {}", quote(&spec.state_dir.to_string_lossy()))
    };
    let program = if runs_by_name(spec) { "harbormaster".to_owned() } else { quote(&spec.program.to_string_lossy()) };
    format!("{program} {arguments}{state_dir}")
}

/// One line on what the daemon is doing, for the end of a command.
fn describe(state: &control::State) -> String {
    let console = match &state.console {
        Some(console) if console.connected => format!("signed in to UniFi Protect at {}", console.host),
        Some(console) if console.waiting_for_password => "waiting for the Protect password".to_owned(),
        Some(console) => format!(
            "not connected to UniFi Protect at {}{}",
            console.host,
            console.problem.as_ref().map_or(String::new(), |why| format!(" ({why})"))
        ),
        None => "no UniFi Protect console configured".to_owned(),
    };
    format!(
        "running: pid {}, version {}, up {}s, {} devices, {console}",
        state.pid,
        state.version,
        state.uptime_secs,
        state.devices.len()
    )
}

fn report_started(spec: &Spec, old_pid: Option<u32>) -> Result<()> {
    let Some(state) = wait_for_daemon(&spec.state_dir, old_pid) else {
        bail!(
            "the service is loaded but the daemon has not answered yet. Look at {} and {}",
            spec.state_dir.join(crate::logfile::FILE_NAME).display(),
            spec.output().display()
        );
    };
    println!("Harbormaster is {}.", describe(&state));
    if state.console.as_ref().is_some_and(|console| console.waiting_for_password) {
        println!("\nGive it the Protect password with:\n\n    {}\n", invocation(spec, "unlock"));
    }
    Ok(())
}

pub fn install(state_dir: &Path, options: &Options) -> Result<()> {
    let manager = manager()?;
    daemon::create_private_dir(state_dir)?;
    let spec = spec(state_dir, options)?;
    let source = std::env::current_exe().context("finding this program's own file")?;
    let binary_changed = install_binary(&source, &spec.program)?;
    if binary_changed {
        println!("Installed the binary at {}.", spec.program.display());
    }
    prepare_output(&spec)?;
    offer_link(&spec);

    let other = Spec { scope: if spec.scope == Scope::System { Scope::User } else { Scope::System }, ..spec.clone() };
    if manager.unit_path(&other).exists() {
        bail!(
            "Harbormaster is already installed the other way, at {}. Remove that first:\n\n    {}\n",
            manager.unit_path(&other).display(),
            invocation(&spec, if other.scope == Scope::User { "service uninstall --user-agent" } else { "service uninstall" })
        );
    }

    let unit = manager.unit(&spec);
    let unit_path = manager.unit_path(&spec);
    let loaded = manager.loaded(&spec).is_some();
    let running = client::state(&spec.state_dir).ok();
    let old_pid = running.as_ref().map(|state| state.pid);

    if loaded && std::fs::read_to_string(&unit_path).is_ok_and(|present| present == unit) {
        // Nothing about the service itself changed. The daemon runs as the
        // owner, so the owner can restart it without administrator rights:
        // it is told to stop and the service manager starts the new binary.
        match old_pid {
            Some(_) if !binary_changed => {
                println!("The service is already installed and up to date.");
                return report_started(&spec, None);
            }
            Some(pid) => {
                println!("Restarting the daemon (pid {pid}) on the new binary...");
                stop_daemon(&spec.state_dir, pid);
            }
            None => println!("The service is installed; waiting for the daemon to start..."),
        }
        return report_started(&spec, old_pid);
    }

    if manager.needs_root(&spec) {
        let staged = spec.state_dir.join("service").join(unit_path.file_name().context("service file has no name")?);
        write_atomically(&staged, &unit)?;
        println!(
            "The service file is ready. Putting it where the system looks takes administrator rights,\n\
             so run these yourself:\n"
        );
        for step in manager.load_steps(&spec, &staged, loaded) {
            println!("    sudo {}", step.shell());
        }
        if let (Some(pid), false) = (old_pid, loaded) {
            println!(
                "\nA daemon is running now (pid {pid}) and the service cannot start beside it.\n\
                 Stop it first, with Ctrl-C in its terminal or:\n\n    kill {pid}"
            );
        }
        println!(
            "\nIt starts at once and again after every reboot. Then check on it and give it the\n\
             Protect password:\n\n    {}\n    {}\n",
            invocation(&spec, "service status"),
            invocation(&spec, "unlock")
        );
        return Ok(());
    }

    // A daemon running by hand would hold the control socket against the
    // service, so it makes way first.
    if let (Some(pid), false) = (old_pid, loaded) {
        println!("Stopping the daemon running now (pid {pid}) so that the service takes over...");
        stop_daemon(&spec.state_dir, pid);
    }
    write_atomically(&unit_path, &unit)?;
    for step in manager.load_steps(&spec, &unit_path, loaded) {
        step.run()?;
    }
    println!("Installed the service at {}.", unit_path.display());
    report_started(&spec, old_pid)
}

pub fn uninstall(state_dir: &Path, options: &Options) -> Result<()> {
    let manager = manager()?;
    let spec = spec(state_dir, options)?;
    let unit_path = manager.unit_path(&spec);
    let loaded = manager.loaded(&spec).is_some();
    if !loaded && !unit_path.exists() {
        println!("No service is installed at {}.", unit_path.display());
        return Ok(());
    }
    let steps = manager.unload_steps(&spec, loaded);
    // The link onto the command path goes too, if it is this installation's.
    let link = Path::new(LINK);
    if linked(&spec.program, link) && std::fs::remove_file(link).is_err() {
        println!("The link at {LINK} is the administrator's to remove:\n\n    sudo /bin/rm {LINK}\n");
    }
    if manager.needs_root(&spec) {
        println!("Removing the service takes administrator rights, so run these yourself:\n");
        for step in steps {
            println!("    sudo {}", step.shell());
        }
        println!("\nThe state directory, with the pairing and the binary, is left as it is.");
        return Ok(());
    }
    for step in steps {
        step.run()?;
    }
    println!("Removed the service. The state directory, with the pairing and the binary, is left as it is.");
    Ok(())
}

/// The installed service, whichever way it was installed.
fn installed(manager: &dyn Manager, state_dir: &Path) -> Result<Spec> {
    let system = spec(state_dir, &Options { scope: Scope::System, listen: None, demo: false })?;
    let user = Spec { scope: Scope::User, ..system.clone() };
    [system.clone(), user]
        .into_iter()
        .find(|spec| manager.unit_path(spec).exists() || manager.loaded(spec).is_some())
        .with_context(|| format!("no service is installed. Install it with:\n\n    {}\n", invocation(&system, "service install")))
}

/// Runs steps here, or prints them when they take administrator rights.
/// Returns whether they were run.
fn carry_out(manager: &dyn Manager, spec: &Spec, steps: Vec<Step>, what: &str) -> Result<bool> {
    if manager.needs_root(spec) {
        println!("{what} takes administrator rights, so run this yourself:\n");
        for step in steps {
            println!("    sudo {}", step.shell());
        }
        println!();
        return Ok(false);
    }
    for step in steps {
        step.run()?;
    }
    Ok(true)
}

/// Restarts the daemon. It runs as the owner, so the owner can tell it to
/// stop, and the service manager starts it again.
pub fn restart(state_dir: &Path) -> Result<()> {
    let manager = manager()?;
    let spec = installed(manager.as_ref(), state_dir)?;
    if manager.loaded(&spec).is_none() {
        bail!("the service is stopped. Start it with:\n\n    {}\n", invocation(&spec, "service start"));
    }
    let old_pid = client::state(&spec.state_dir).ok().map(|state| state.pid);
    match old_pid {
        Some(pid) => {
            println!("Restarting the daemon (pid {pid})...");
            stop_daemon(&spec.state_dir, pid);
        }
        None => println!("No daemon is answering; waiting for the service to start one..."),
    }
    report_started(&spec, old_pid)
}

/// Stops the service until `service start` or the next reboot.
pub fn stop(state_dir: &Path) -> Result<()> {
    let manager = manager()?;
    let spec = installed(manager.as_ref(), state_dir)?;
    if manager.loaded(&spec).is_none() {
        println!("The service is already stopped.");
        return Ok(());
    }
    if carry_out(manager.as_ref(), &spec, manager.stop_steps(&spec), "Stopping the service")? {
        println!("Stopped.");
    }
    println!(
        "It stays stopped until the machine restarts or you run:\n\n    {}\n",
        invocation(&spec, "service start")
    );
    Ok(())
}

/// Starts a service stopped with `service stop`.
pub fn start(state_dir: &Path) -> Result<()> {
    let manager = manager()?;
    let spec = installed(manager.as_ref(), state_dir)?;
    if manager.loaded(&spec).is_some() {
        println!("The service is already started.");
        return report_started(&spec, None);
    }
    if carry_out(manager.as_ref(), &spec, manager.start_steps(&spec), "Starting the service")? {
        return report_started(&spec, None);
    }
    println!("Then give it the Protect password:\n\n    {}\n", invocation(&spec, "unlock"));
    Ok(())
}

/// Says what is installed and what is running. Fails if no daemon answers.
pub fn status(state_dir: &Path) -> Result<()> {
    let manager = manager()?;
    let options = Options { scope: Scope::System, listen: None, demo: false };
    let system = spec(state_dir, &options)?;
    let mut installed = false;
    for (name, spec) in [("system service", system.clone()), ("user agent", Spec { scope: Scope::User, ..system.clone() })] {
        let unit_path = manager.unit_path(&spec);
        let loaded = manager.loaded(&spec);
        if !unit_path.exists() && loaded.is_none() {
            continue;
        }
        installed = true;
        let file = if unit_path.exists() { unit_path.display().to_string() } else { "its file is missing".to_owned() };
        println!("Service: {name} ({file}), {}", loaded.unwrap_or_else(|| "not loaded".to_owned()));
    }
    if !installed {
        println!("Service: not installed. Install it with:\n\n    {}\n", invocation(&system, "service install"));
    }
    println!("Log:     {}", system.state_dir.join(crate::logfile::FILE_NAME).display());
    match client::state(&system.state_dir) {
        Ok(state) => {
            println!("Daemon:  {}", describe(&state));
            if state.console.as_ref().is_some_and(|console| console.waiting_for_password) {
                println!("\nGive it the Protect password with:\n\n    {}\n", invocation(&system, "unlock"));
            }
            Ok(())
        }
        Err(_) => bail!("Daemon:  not running"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_path_link_replaces_a_stale_link_but_never_a_file() {
        let dir = temp_dir("link");
        let (program, link) = (dir.join("bin/harbormaster"), dir.join("path/harbormaster"));
        assert!(!linked(&program, &link));
        assert!(link_binary(&program, &link), "the directory is made if need be");
        assert!(linked(&program, &link) && link_binary(&program, &link), "and once is enough");
        // A link left by an installation elsewhere is pointed here.
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), &link).unwrap();
        assert!(link_binary(&program, &link) && linked(&program, &link));
        // A copy a package manager put on the command path needs no link.
        let brew = dir.join("brew");
        std::fs::create_dir_all(&brew).unwrap();
        let path = std::env::join_paths([dir.join("path"), brew.clone()]).unwrap();
        assert!(!on_path_elsewhere(Some(&path), &link), "the link itself does not count");
        std::fs::write(brew.join("harbormaster"), "").unwrap();
        assert!(!on_path_elsewhere(Some(&path), &link), "nor does a file that cannot be run");
        std::fs::set_permissions(brew.join("harbormaster"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        assert!(on_path_elsewhere(Some(&path), &link) && !on_path_elsewhere(None, &link));
        // Some other program of the same name is left alone.
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&link, "not ours").unwrap();
        assert!(!link_binary(&program, &link));
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "not ours");
        std::fs::remove_dir_all(&dir).unwrap();
    }
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hm-service-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_binary_is_replaced_by_rename_and_never_written_in_place() {
        use std::os::unix::fs::MetadataExt;
        let dir = temp_dir("binary");
        let source = dir.join("harbormaster.download");
        std::fs::write(&source, b"version one").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        let destination = installed_binary(&dir);

        assert!(install_binary(&source, &destination).unwrap());
        assert_eq!(std::fs::read(&destination).unwrap(), b"version one");
        assert_eq!(std::fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o755);
        let first = std::fs::metadata(&destination).unwrap().ino();
        // A process running the old file keeps it open, like this handle.
        let running = std::fs::File::open(&destination).unwrap();

        // The same binary again changes nothing.
        assert!(!install_binary(&source, &destination).unwrap());
        assert_eq!(std::fs::metadata(&destination).unwrap().ino(), first);

        std::fs::write(&source, b"version two").unwrap();
        assert!(install_binary(&source, &destination).unwrap());
        assert_eq!(std::fs::read(&destination).unwrap(), b"version two");
        assert_ne!(std::fs::metadata(&destination).unwrap().ino(), first, "a new file, not the old one rewritten");
        let mut old = String::new();
        std::io::Read::read_to_string(&mut { running }, &mut old).unwrap();
        assert_eq!(old, "version one", "the running copy is untouched");
        assert!(!destination.with_extension("new").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn commands_are_quoted_for_a_shell_only_where_needed() {
        let step = Step::new(["/bin/launchctl", "bootstrap", "gui/501"]).path(Path::new("/Users/pat/It's here/x.plist"));
        assert_eq!(step.shell(), r"/bin/launchctl bootstrap gui/501 '/Users/pat/It'\''s here/x.plist'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn a_large_output_file_is_emptied_and_a_small_one_kept() {
        let dir = temp_dir("output");
        let path = dir.join(OUTPUT_NAME);
        std::fs::write(&path, "a failed start\n").unwrap();
        trim_output(&dir);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a failed start\n");
        std::fs::write(&path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        trim_output(&dir);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_daemon_is_described_in_one_line() {
        let mut state = control::State { pid: 612, version: "0.1.0".into(), uptime_secs: 9, ..Default::default() };
        assert!(describe(&state).ends_with("0 devices, no UniFi Protect console configured"));
        state.console = Some(control::Console { host: "h".into(), waiting_for_password: true, ..Default::default() });
        assert_eq!(describe(&state), "running: pid 612, version 0.1.0, up 9s, 0 devices, waiting for the Protect password");
        state.console = Some(control::Console { host: "h".into(), problem: Some("no route".into()), ..Default::default() });
        assert!(describe(&state).ends_with("not connected to UniFi Protect at h (no route)"));
    }
}
