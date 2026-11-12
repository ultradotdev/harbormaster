//! Messages the daemon sends to an attached TUI over its control socket,
//! one JSON object per line.

use serde::{Deserialize, Serialize};

/// File name of the control socket inside the state directory.
pub const SOCKET_NAME: &str = "control.sock";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// A full status snapshot, sent on connect and then once a second.
    State(Box<State>),
    Log(LogLine),
}

/// What an attached TUI may ask of the daemon, one JSON object per line.
/// The socket is the owner's alone, so these need no further permission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// Share a device with HomeKit, or stop sharing it.
    SetShared { key: String, shared: bool },
    /// Publish a device under a new name, or under its own again if absent.
    Rename {
        key: String,
        #[serde(default)]
        name: Option<String>,
    },
    /// Put this text before every name sent to HomeKit. Absent means
    /// whatever `config.toml` says.
    SetNamePrefix {
        #[serde(default)]
        text: Option<String>,
    },
    /// The same, after every name.
    SetNameSuffix {
        #[serde(default)]
        text: Option<String>,
    },
}

/// Every struct here defaults its missing fields and ignores unknown ones,
/// so a TUI and a daemon of different versions can still talk.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub name: String,
    pub version: String,
    pub listen: String,
    pub uptime_secs: u64,
    pub paired: bool,
    /// Present only while unpaired.
    pub setup_code: Option<String>,
    pub setup_uri: Option<String>,
    pub controllers: Vec<Controller>,
    pub connections: Vec<Connection>,
    /// The raw HomeKit view, which is all that older TUIs know to show.
    pub accessories: Vec<Accessory>,
    /// The daemon's clock when this was taken, in seconds since the Unix
    /// epoch. Ages are worked out against this, not the TUI's own clock.
    pub time: u64,
    /// HomeKit's configuration number, which rises when accessories change.
    pub config_number: u32,
    /// Text put before and after every device name sent to HomeKit. Device
    /// names in this snapshot are plain: they never include it.
    pub name_prefix: String,
    pub name_suffix: String,
    /// Absent when no UniFi Protect console is configured.
    pub console: Option<Console>,
    pub devices: Vec<Device>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Controller {
    pub id: String,
    pub admin: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Connection {
    pub peer: String,
    pub controller: Option<String>,
    pub connected_secs: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Accessory {
    pub aid: u64,
    pub name: String,
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub readings: Vec<Reading>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Reading {
    pub label: String,
    pub value: String,
}

/// The connection to the UniFi Protect console.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Console {
    pub host: String,
    pub connected: bool,
    /// When the console last sent anything, in seconds since the Unix epoch.
    pub last_update: Option<u64>,
}

/// One published device and what it is doing. Times are seconds since the
/// Unix epoch; a fact that does not apply to the device is absent.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Device {
    pub aid: u64,
    /// Identifies the device in commands. Absent if it cannot be edited.
    pub key: Option<String>,
    /// The owner chose not to share this device with HomeKit.
    pub hidden: bool,
    /// The device's own name, when it is published under another.
    pub protect_name: Option<String>,
    /// "camera", "doorbell", "light" or "sensor".
    pub kind: String,
    pub name: String,
    pub model: String,
    pub serial_number: String,
    pub online: Option<bool>,
    pub motion: Option<bool>,
    pub last_motion: Option<u64>,
    pub last_ring: Option<u64>,
    pub light_on: Option<bool>,
    /// Percent.
    pub brightness: Option<u8>,
    /// Percent.
    pub battery: Option<u8>,
    pub low_battery: Option<bool>,
    pub tampered: Option<bool>,
    /// Sensor readings such as temperature, already formatted.
    pub readings: Vec<Reading>,
    /// People watching the camera live right now.
    pub viewers: Vec<Viewer>,
    /// Present for cameras that can record for HomeKit.
    pub recording: Option<Recording>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Viewer {
    pub peer: String,
    pub width: u16,
    pub height: u16,
    pub secs: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Recording {
    /// Whether recording is switched on in HomeKit.
    pub enabled: bool,
    /// How long the recording in progress has run, if there is one.
    pub active_secs: Option<u64>,
    /// When the last finished recording began, and how long it ran.
    pub last_at: Option<u64>,
    pub last_secs: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogLine {
    /// Seconds since the Unix epoch.
    pub time: u64,
    pub level: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly what a daemon from before the dashboard sends.
    const OLD_STATE: &str = r#"{"type":"state","name":"Harbormaster 6C2C","version":"0.1.0","listen":"[::]:51826",
        "uptime_secs":5,"paired":true,"setup_code":null,"setup_uri":null,
        "controllers":[{"id":"AAAA","admin":true}],
        "connections":[{"peer":"10.0.0.5","controller":"AAAA","connected_secs":3}],
        "accessories":[{"aid":2,"name":"Porch","manufacturer":"Acme","model":"T1","serial_number":"s1",
                        "readings":[{"label":"Temperature","value":"21.5 °C"}]}]}"#;

    #[test]
    fn old_daemon_snapshot_still_reads() {
        let Message::State(state) = serde_json::from_str(OLD_STATE).unwrap() else { panic!("not a state") };
        assert_eq!((state.name.as_str(), state.paired, state.accessories.len()), ("Harbormaster 6C2C", true, 1));
        assert_eq!(state.connections[0].peer, "10.0.0.5");
        assert!(state.devices.is_empty() && state.console.is_none());
        assert_eq!((state.time, state.config_number), (0, 0));
    }

    #[test]
    fn new_snapshot_round_trips() {
        let state = State {
            name: "Harbormaster".into(),
            time: 1_800_000_000,
            config_number: 7,
            console: Some(Console { host: "10.0.0.1".into(), connected: true, last_update: Some(1_799_999_998) }),
            devices: vec![Device {
                aid: 3,
                kind: "doorbell".into(),
                name: "Front Door".into(),
                online: Some(true),
                motion: Some(false),
                last_ring: Some(1_799_999_000),
                viewers: vec![Viewer { peer: "10.0.0.5".into(), width: 1280, height: 720, secs: 9 }],
                recording: Some(Recording { enabled: true, active_secs: None, last_at: Some(1), last_secs: Some(19) }),
                ..Device::default()
            }],
            ..State::default()
        };
        let line = serde_json::to_string(&Message::State(Box::new(state.clone()))).unwrap();
        let Message::State(back) = serde_json::from_str(&line).unwrap() else { panic!("not a state") };
        assert_eq!(*back, state);
    }

    #[test]
    fn unknown_and_missing_fields_are_tolerated() {
        // A future daemon: fields this build has never heard of, at every level.
        let future = r#"{"type":"state","name":"H","mood":"calm","console":{"host":"h","latency_ms":3},
            "devices":[{"aid":4,"kind":"camera","lens":"wide","viewers":[{"peer":"p","codec":"h264"}],
                        "recording":{"enabled":true,"clips":12}}]}"#;
        let Message::State(state) = serde_json::from_str(future).unwrap() else { panic!("not a state") };
        assert_eq!(state.devices[0].viewers[0].peer, "p");
        assert!(state.devices[0].recording.as_ref().unwrap().enabled);
        assert_eq!(state.console.unwrap().last_update, None);
        // Nothing but the tag.
        assert!(matches!(serde_json::from_str(r#"{"type":"state"}"#).unwrap(), Message::State(_)));
        assert!(matches!(serde_json::from_str(r#"{"type":"log","message":"m"}"#).unwrap(), Message::Log(_)));
        // A message kind this build does not know is an error the TUI skips.
        assert!(serde_json::from_str::<Message>(r#"{"type":"metrics"}"#).is_err());
    }

    #[test]
    fn commands_have_a_stable_wire_form() {
        let share = Command::SetShared { key: "protect:camera:cam1".into(), shared: false };
        assert_eq!(
            serde_json::to_string(&share).unwrap(),
            r#"{"type":"set_shared","key":"protect:camera:cam1","shared":false}"#
        );
        let rename: Command = serde_json::from_str(r#"{"type":"rename","key":"k","extra":1}"#).unwrap();
        assert_eq!(rename, Command::Rename { key: "k".into(), name: None });
        assert!(serde_json::from_str::<Command>(r#"{"type":"reboot"}"#).is_err());
        // Spaces in a prefix are part of it and must survive the trip.
        let prefix = Command::SetNamePrefix { text: Some("HM ".into()) };
        let line = serde_json::to_string(&prefix).unwrap();
        assert_eq!(line, r#"{"type":"set_name_prefix","text":"HM "}"#);
        assert_eq!(serde_json::from_str::<Command>(&line).unwrap(), prefix);
        let default: Command = serde_json::from_str(r#"{"type":"set_name_suffix"}"#).unwrap();
        assert_eq!(default, Command::SetNameSuffix { text: None });
    }

    /// The fields a TUI from before the dashboard insists on must stay.
    #[test]
    fn new_snapshot_keeps_every_field_an_old_tui_requires() {
        let value = serde_json::to_value(Message::State(Box::default())).unwrap();
        for field in ["name", "version", "listen", "uptime_secs", "paired", "controllers", "connections", "accessories"] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
    }
}
