//! Running Harbormaster under launchd, the macOS service manager.
//!
//! Two kinds of launchd job could run the bridge:
//!
//! * A per-user LaunchAgent (`~/Library/LaunchAgents`) needs no
//!   administrator rights, but belongs to the user's login session: it
//!   starts when that user logs in at the screen and is gone when they log
//!   out. On a headless Mac reached only over SSH nobody ever logs in at
//!   the screen, so after a reboot the bridge would stay down. Programs run
//!   as agents are also subject to macOS's local-network privacy prompt,
//!   which nobody is there to answer.
//! * A system LaunchDaemon (`/Library/LaunchDaemons`) starts at boot with
//!   nobody logged in. With `UserName` it runs as the owner rather than as
//!   root, so it can do nothing the owner could not. Installing it takes
//!   `sudo` once.
//!
//! The bridge has to come back after a reboot of an unattended machine, so
//! the system LaunchDaemon running as the owner is the default. The price
//! is that such a job runs outside any login session and cannot read the
//! login Keychain, which is why the daemon waits for `harbormaster unlock`.
//! The LaunchAgent is still offered (`--user-agent`) for a Mac that always
//! has its owner logged in, and for trying the service out without `sudo`.
//!
//! The property list holds paths and a user name, never a secret.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::service::{Manager, Scope, Spec, Step};

pub struct Launchd;

/// An absolute path, so a planted `launchctl` on PATH is never run.
const LAUNCHCTL: &str = "/bin/launchctl";

fn file_name(spec: &Spec) -> String {
    format!("{}.plist", spec.label)
}

/// The launchd domain the job lives in.
fn domain(spec: &Spec) -> String {
    match spec.scope {
        Scope::System => "system".to_owned(),
        Scope::User => format!("gui/{}", spec.uid),
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn string(text: impl AsRef<str>) -> String {
    format!("<string>{}</string>", escape(text.as_ref()))
}

fn path(path: &Path) -> String {
    string(path.to_string_lossy())
}

/// The property list that runs the daemon.
pub fn plist(spec: &Spec) -> String {
    let arguments: String = spec.arguments().iter().map(|a| format!("\n        {}", string(a))).collect();
    // Only a system job chooses its user; an agent is already the user's.
    let user = match spec.scope {
        Scope::System => format!("\n    <key>UserName</key>\n    {}", string(&spec.user)),
        Scope::User => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    {label}
    <key>ProgramArguments</key>
    <array>{arguments}
    </array>{user}
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>WorkingDirectory</key>
    {state_dir}
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        {home}
    </dict>
    <key>StandardOutPath</key>
    {output}
    <key>StandardErrorPath</key>
    {output}
</dict>
</plist>
"#,
        label = string(&spec.label),
        state_dir = path(&spec.state_dir),
        home = path(&spec.home),
        output = path(&spec.output()),
    )
}

impl Manager for Launchd {
    fn unit_path(&self, spec: &Spec) -> PathBuf {
        match spec.scope {
            Scope::System => Path::new("/Library/LaunchDaemons").join(file_name(spec)),
            Scope::User => spec.home.join("Library/LaunchAgents").join(file_name(spec)),
        }
    }

    fn unit(&self, spec: &Spec) -> String {
        plist(spec)
    }

    fn needs_root(&self, spec: &Spec) -> bool {
        spec.scope == Scope::System
    }

    fn load_steps(&self, spec: &Spec, staged: &Path, loaded: bool) -> Vec<Step> {
        let unit = self.unit_path(spec);
        let mut steps = Vec::new();
        if loaded {
            steps.push(Step::new([LAUNCHCTL, "bootout", &format!("{}/{}", domain(spec), spec.label)]));
        }
        if self.needs_root(spec) {
            // launchd refuses a system job whose file is not root's.
            steps.push(Step::new(["/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "644"]).path(staged).path(&unit));
        }
        steps.push(Step::new([LAUNCHCTL, "bootstrap", &domain(spec)]).path(&unit).retried());
        steps
    }

    fn unload_steps(&self, spec: &Spec, loaded: bool) -> Vec<Step> {
        let mut steps = Vec::new();
        if loaded {
            steps.push(Step::new([LAUNCHCTL, "bootout", &format!("{}/{}", domain(spec), spec.label)]));
        }
        steps.push(Step::new(["/bin/rm", "-f"]).path(&self.unit_path(spec)));
        steps
    }

    fn stop_steps(&self, spec: &Spec) -> Vec<Step> {
        // Unloading is the only way to stop a job that launchd keeps alive.
        vec![Step::new([LAUNCHCTL, "bootout", &format!("{}/{}", domain(spec), spec.label)])]
    }

    fn start_steps(&self, spec: &Spec) -> Vec<Step> {
        vec![Step::new([LAUNCHCTL, "bootstrap", &domain(spec)]).path(&self.unit_path(spec)).retried()]
    }

    fn loaded(&self, spec: &Spec) -> Option<String> {
        let output = Command::new(LAUNCHCTL)
            .args(["print", &format!("{}/{}", domain(spec), spec.label)])
            .stdin(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(summary(&String::from_utf8_lossy(&output.stdout)))
    }
}

/// The few lines of `launchctl print` worth showing.
fn summary(printed: &str) -> String {
    let field = |name: &str| {
        printed.lines().map(str::trim).find_map(|line| line.strip_prefix(name)?.strip_prefix(" = ")).map(str::to_owned)
    };
    let mut parts = vec![field("state").unwrap_or_else(|| "loaded".to_owned())];
    if let Some(pid) = field("pid") {
        parts.push(format!("pid {pid}"));
    }
    if let Some(code) = field("last exit code") {
        parts.push(format!("last exit {code}"));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn spec(scope: Scope) -> Spec {
        Spec {
            label: "dev.ultra.harbormaster".into(),
            scope,
            program: "/Users/pat/Library/Application Support/harbormaster/bin/harbormaster".into(),
            state_dir: "/Users/pat/Library/Application Support/harbormaster".into(),
            user: "pat".into(),
            uid: 501,
            home: "/Users/pat".into(),
            listen: None,
            demo: false,
        }
    }

    /// The strings of a property list, in order, with entities undone.
    fn strings(plist: &str) -> Vec<String> {
        plist
            .split("<string>")
            .skip(1)
            .map(|rest| rest.split("</string>").next().unwrap().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))
            .collect()
    }

    #[test]
    fn the_system_job_runs_the_daemon_as_the_owner_from_the_state_directory() {
        let text = plist(&spec(Scope::System));
        let dir = "/Users/pat/Library/Application Support/harbormaster";
        assert_eq!(
            strings(&text),
            [
                "dev.ultra.harbormaster",
                &format!("{dir}/bin/harbormaster"),
                "daemon",
                "--detached",
                "--state-dir",
                dir,
                "pat",
                "Interactive",
                dir,
                "/Users/pat",
                &format!("{dir}/service.out"),
                &format!("{dir}/service.out"),
            ]
        );
        assert!(text.contains("<key>UserName</key>\n    <string>pat</string>"));
        assert!(text.contains("<key>KeepAlive</key>\n    <true/>") && text.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert_eq!(Launchd.unit_path(&spec(Scope::System)), Path::new("/Library/LaunchDaemons/dev.ultra.harbormaster.plist"));
        assert!(Launchd.needs_root(&spec(Scope::System)));
    }

    #[test]
    fn the_agent_names_no_user_and_lives_in_the_owners_library() {
        let agent = spec(Scope::User);
        let text = plist(&agent);
        assert!(!text.contains("UserName"));
        assert_eq!(Launchd.unit_path(&agent), Path::new("/Users/pat/Library/LaunchAgents/dev.ultra.harbormaster.plist"));
        assert!(!Launchd.needs_root(&agent));
        let steps: Vec<String> =
            Launchd.load_steps(&agent, Path::new("/unused"), true).iter().map(Step::shell).collect();
        assert_eq!(
            steps,
            [
                "/bin/launchctl bootout gui/501/dev.ultra.harbormaster",
                "/bin/launchctl bootstrap gui/501 /Users/pat/Library/LaunchAgents/dev.ultra.harbormaster.plist",
            ]
        );
    }

    #[test]
    fn the_system_job_is_put_in_place_as_root_and_only_booted_out_if_loaded() {
        let system = spec(Scope::System);
        let staged = Path::new("/Users/pat/Library/Application Support/harbormaster/service/dev.ultra.harbormaster.plist");
        let steps: Vec<String> = Launchd.load_steps(&system, staged, false).iter().map(Step::shell).collect();
        assert_eq!(
            steps,
            [
                "/usr/bin/install -o root -g wheel -m 644 '/Users/pat/Library/Application Support/harbormaster/service/dev.ultra.harbormaster.plist' /Library/LaunchDaemons/dev.ultra.harbormaster.plist",
                "/bin/launchctl bootstrap system /Library/LaunchDaemons/dev.ultra.harbormaster.plist",
            ]
        );
        let unload: Vec<String> = Launchd.unload_steps(&system, true).iter().map(Step::shell).collect();
        assert_eq!(
            unload,
            [
                "/bin/launchctl bootout system/dev.ultra.harbormaster",
                "/bin/rm -f /Library/LaunchDaemons/dev.ultra.harbormaster.plist",
            ]
        );
        // Stopping leaves the file where it is, for starting again.
        let stop: Vec<String> = Launchd.stop_steps(&system).iter().map(Step::shell).collect();
        assert_eq!(stop, ["/bin/launchctl bootout system/dev.ultra.harbormaster"]);
        let start: Vec<String> = Launchd.start_steps(&system).iter().map(Step::shell).collect();
        assert_eq!(start, ["/bin/launchctl bootstrap system /Library/LaunchDaemons/dev.ultra.harbormaster.plist"]);
    }

    #[test]
    fn options_are_passed_on_and_awkward_paths_are_escaped() {
        let mut odd = spec(Scope::User);
        odd.state_dir = "/Users/pat/R&D <test>".into();
        odd.listen = Some("127.0.0.1:51900".parse::<SocketAddr>().unwrap());
        odd.demo = true;
        let text = plist(&odd);
        assert!(text.contains("<string>/Users/pat/R&amp;D &lt;test&gt;</string>"), "{text}");
        let all = strings(&text);
        assert_eq!(all[2..9], ["daemon", "--detached", "--state-dir", "/Users/pat/R&D <test>", "--listen", "127.0.0.1:51900", "--demo"]);
    }

    /// Nothing in the file is a secret, whatever lies in the state directory.
    #[test]
    fn the_property_list_holds_no_secrets() {
        let dir = std::env::temp_dir().join(format!("hm-launchd-{}-plain", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(crate::secrets::PROTECT_PASSWORD_FILE), "correct horse\n").unwrap();
        let mut here = spec(Scope::System);
        here.state_dir = dir.clone();
        let text = plist(&here);
        assert!(!text.contains("horse"));
        for word in ["password", "Password", "secret", "token", "protect-password"] {
            assert!(!text.contains(word), "{word} in {text}");
        }
        // Every string in it is one of the things it is meant to hold.
        let state_dir = dir.to_string_lossy().into_owned();
        for value in strings(&text) {
            let known = ["dev.ultra.harbormaster", "daemon", "--detached", "--state-dir", "pat", "Interactive", "/Users/pat"];
            let expected = known.contains(&value.as_str())
                || value == state_dir
                || value == format!("{state_dir}/service.out")
                || value == here.program.to_string_lossy();
            assert!(expected, "unexpected {value}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// macOS's own checker must accept the file, for both kinds of job.
    #[cfg(target_os = "macos")]
    #[test]
    fn plutil_accepts_the_property_list() {
        let dir = std::env::temp_dir().join(format!("hm-launchd-{}-lint", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, scope) in [("system.plist", Scope::System), ("agent.plist", Scope::User)] {
            let mut odd = spec(scope);
            odd.state_dir = "/Users/pat/R&D <test>".into();
            let file = dir.join(name);
            std::fs::write(&file, plist(&odd)).unwrap();
            let Ok(output) = Command::new("/usr/bin/plutil").arg("-lint").arg(&file).output() else { return };
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            // And it reads back what was put in.
            let read = Command::new("/usr/bin/plutil")
                .args(["-extract", "WorkingDirectory", "raw", "-o", "-"])
                .arg(&file)
                .output()
                .unwrap();
            assert_eq!(String::from_utf8_lossy(&read.stdout).trim(), "/Users/pat/R&D <test>");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn launchctl_output_is_boiled_down() {
        let printed = "system/dev.ultra.harbormaster = {\n\tactive count = 1\n\tstate = running\n\n\tprogram = /x\n\tpid = 612\n\tlast exit code = (never exited)\n}\n";
        assert_eq!(summary(printed), "running, pid 612, last exit (never exited)");
        assert_eq!(summary("x = {\n\tstate = not running\n\tlast exit code = 1\n}"), "not running, last exit 1");
    }
}
