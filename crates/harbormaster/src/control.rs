//! Messages the daemon sends to an attached TUI over its control socket,
//! one JSON object per line.

use serde::{Deserialize, Serialize};

/// File name of the control socket inside the state directory.
pub const SOCKET_NAME: &str = "control.sock";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// A full status snapshot, sent on connect and then once a second.
    State(State),
    Log(LogLine),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    pub accessories: Vec<Accessory>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Controller {
    pub id: String,
    pub admin: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub peer: String,
    pub controller: Option<String>,
    pub connected_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Accessory {
    pub aid: u64,
    pub name: String,
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub readings: Vec<Reading>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reading {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogLine {
    /// Seconds since the Unix epoch.
    pub time: u64,
    pub level: String,
    pub message: String,
}
