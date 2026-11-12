//! What the bridge is doing right now, gathered for the dashboard.
//!
//! The parts that talk to the console, serve live video and make recordings
//! each report here with a single call, and the daemon reads the lot when it
//! builds a snapshot for an attached TUI. Nothing secret is ever recorded:
//! no keys, no credentials and no stream addresses, only who is watching
//! what and when things happened.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use harbormaster_hap::model::kind;
use harbormaster_hap::Database;
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

struct Inner {
    console_connected: bool,
    console_last_update: Option<u64>,
    /// What kind of Protect device each accessory is.
    kinds: BTreeMap<u64, &'static str>,
    last_motion: BTreeMap<u64, u64>,
    last_ring: BTreeMap<u64, u64>,
    next_id: u64,
    viewers: BTreeMap<u64, Viewing>,
    recordings: BTreeMap<u64, Recording>,
    /// When each camera's last finished recording began and how long it ran,
    /// by camera name.
    last_recording: BTreeMap<String, (u64, u64)>,
}

struct Viewing {
    aid: u64,
    peer: IpAddr,
    width: u16,
    height: u16,
    began: Instant,
}

struct Recording {
    camera: String,
    began: Instant,
    began_at: u64,
}

pub struct Status {
    inner: Mutex<Inner>,
}

static GLOBAL: Status = Status::new();

/// The one status board of this process.
pub fn global() -> &'static Status {
    &GLOBAL
}

/// Marks a live view or a recording as in progress until it is dropped.
pub struct Guard<'a> {
    status: &'a Status,
    id: u64,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let mut inner = self.status.lock();
        inner.viewers.remove(&self.id);
        if let Some(recording) = inner.recordings.remove(&self.id) {
            let ran = recording.began.elapsed().as_secs();
            inner.last_recording.insert(recording.camera, (recording.began_at, ran));
        }
    }
}

/// A copy of the board at one moment.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub console_connected: bool,
    pub console_last_update: Option<u64>,
    pub kinds: BTreeMap<u64, &'static str>,
    pub last_motion: BTreeMap<u64, u64>,
    pub last_ring: BTreeMap<u64, u64>,
    pub viewers: Vec<Viewer>,
    /// Seconds each recording in progress has run, by camera name.
    pub recording: BTreeMap<String, u64>,
    pub last_recording: BTreeMap<String, (u64, u64)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Viewer {
    pub aid: u64,
    pub peer: IpAddr,
    pub width: u16,
    pub height: u16,
    pub secs: u64,
}

impl Status {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                console_connected: false,
                console_last_update: None,
                kinds: BTreeMap::new(),
                last_motion: BTreeMap::new(),
                last_ring: BTreeMap::new(),
                next_id: 0,
                viewers: BTreeMap::new(),
                recordings: BTreeMap::new(),
                last_recording: BTreeMap::new(),
            }),
        }
    }

    /// A status display must never take the bridge down, so a panic
    /// elsewhere while holding the lock is shrugged off.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The console sent something, so the connection is alive.
    pub fn console_update(&self) {
        let mut inner = self.lock();
        inner.console_connected = true;
        inner.console_last_update = Some(unix_now());
    }

    pub fn console_disconnected(&self) {
        self.lock().console_connected = false;
    }

    /// Notes what kind of Protect device an accessory is ("camera",
    /// "sensor" or "light").
    pub fn device_kind(&self, aid: u64, kind: &'static str) {
        self.lock().kinds.insert(aid, kind);
    }

    pub fn motion(&self, aid: u64) {
        self.lock().last_motion.insert(aid, unix_now());
    }

    pub fn ring(&self, aid: u64) {
        self.lock().last_ring.insert(aid, unix_now());
    }

    /// Someone is watching a camera live, until the guard is dropped.
    pub fn viewing(&self, aid: u64, peer: IpAddr, width: u16, height: u16) -> Guard<'_> {
        let mut inner = self.lock();
        inner.next_id += 1;
        let id = inner.next_id;
        inner.viewers.insert(id, Viewing { aid, peer, width, height, began: Instant::now() });
        Guard { status: self, id }
    }

    /// A recording of the named camera is in progress, until the guard is
    /// dropped.
    pub fn recording(&self, camera: &str) -> Guard<'_> {
        let mut inner = self.lock();
        inner.next_id += 1;
        let id = inner.next_id;
        inner.recordings.insert(id, Recording { camera: camera.to_owned(), began: Instant::now(), began_at: unix_now() });
        Guard { status: self, id }
    }

    pub fn snapshot(&self) -> Snapshot {
        let inner = self.lock();
        Snapshot {
            console_connected: inner.console_connected,
            console_last_update: inner.console_last_update,
            kinds: inner.kinds.clone(),
            last_motion: inner.last_motion.clone(),
            last_ring: inner.last_ring.clone(),
            viewers: inner
                .viewers
                .values()
                .map(|v| Viewer {
                    aid: v.aid,
                    peer: v.peer,
                    width: v.width,
                    height: v.height,
                    secs: v.began.elapsed().as_secs(),
                })
                .collect(),
            recording: inner.recordings.values().map(|r| (r.camera.clone(), r.began.elapsed().as_secs())).collect(),
            last_recording: inner.last_recording.clone(),
        }
    }

    /// Notes one change to the HomeKit database: motion beginning, or a
    /// doorbell press.
    fn observe(&self, db: &Database, aid: u64, iid: u64, value: &serde_json::Value) {
        match db.with(aid, iid, |c| c.kind) {
            Some(kind::MOTION_DETECTED) if *value == json!(true) => self.motion(aid),
            Some(kind::PROGRAMMABLE_SWITCH_EVENT) => self.ring(aid),
            _ => {}
        }
    }
}

/// Follows the HomeKit database so the board knows when each device last
/// saw motion or was rung, without the integrations having to say so.
pub fn watch(status: &'static Status, db: &Arc<Database>) {
    let mut changes = db.subscribe_changes();
    let db = db.clone();
    tokio::spawn(async move {
        loop {
            match changes.recv().await {
                Ok(change) => status.observe(&db, change.aid, change.iid, &change.value),
                // Missing a burst only costs a "last motion" time.
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use harbormaster_hap::{Accessory, Characteristic, Format, Info};

    #[test]
    fn guards_track_viewers_and_recordings() {
        let status = Status::new();
        let viewer = status.viewing(3, "10.0.0.5".parse().unwrap(), 1280, 720);
        let recording = status.recording("Front Door");
        let now = status.snapshot();
        assert_eq!(now.viewers.len(), 1);
        assert_eq!((now.viewers[0].aid, now.viewers[0].width), (3, 1280));
        assert!(now.recording.contains_key("Front Door") && now.last_recording.is_empty());

        drop(viewer);
        drop(recording);
        let after = status.snapshot();
        assert!(after.viewers.is_empty() && after.recording.is_empty());
        assert!(after.last_recording.contains_key("Front Door"));
    }

    #[test]
    fn console_state_follows_updates() {
        let status = Status::new();
        assert!(!status.snapshot().console_connected);
        status.console_update();
        let up = status.snapshot();
        assert!(up.console_connected && up.console_last_update.is_some());
        status.console_disconnected();
        let down = status.snapshot();
        assert!(!down.console_connected);
        assert_eq!(down.console_last_update, up.console_last_update, "the last update time is kept");
    }

    #[test]
    fn database_changes_date_motion_and_rings() {
        let db = Database::new();
        let info =
            Info { name: "Door", manufacturer: "m", model: "m", serial_number: "s", firmware_revision: "1" };
        let mut accessory = Accessory::new(2, &info);
        let ids = accessory.add_service(
            kind::MOTION_SENSOR,
            true,
            vec![
                Characteristic::sensor(kind::MOTION_DETECTED, Format::Bool, json!(false)),
                Characteristic::sensor(kind::PROGRAMMABLE_SWITCH_EVENT, Format::Uint8, json!(null)),
            ],
        );
        db.add(accessory);
        let status = Status::new();
        status.observe(&db, 2, ids[0], &json!(false));
        assert!(status.snapshot().last_motion.is_empty(), "motion ending is not motion");
        status.observe(&db, 2, ids[0], &json!(true));
        status.observe(&db, 2, ids[1], &json!(0));
        status.observe(&db, 9, 1, &json!(true));
        let snapshot = status.snapshot();
        assert!(snapshot.last_motion.contains_key(&2) && snapshot.last_ring.contains_key(&2));
        assert_eq!(snapshot.last_motion.len(), 1);
    }
}
