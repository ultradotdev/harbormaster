//! The accessory database: accessories, their services and characteristics,
//! and the change notifications that drive HomeKit events.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use serde_json::{json, Map, Value};
use tokio::sync::broadcast;

/// HAP status codes returned per characteristic.
pub mod status {
    pub const OK: i32 = 0;
    pub const INSUFFICIENT_PRIVILEGES: i32 = -70401;
    pub const READ_ONLY: i32 = -70404;
    pub const WRITE_ONLY: i32 = -70405;
    pub const NO_NOTIFICATIONS: i32 = -70406;
    pub const NOT_FOUND: i32 = -70409;
    pub const INVALID_VALUE: i32 = -70410;
}

/// Short-form Apple-defined type identifiers.
pub mod kind {
    pub const ACCESSORY_INFORMATION: &str = "3E";
    pub const PROTOCOL_INFORMATION: &str = "A2";
    pub const TEMPERATURE_SENSOR: &str = "8A";
    pub const HUMIDITY_SENSOR: &str = "82";

    pub const IDENTIFY: &str = "14";
    pub const MANUFACTURER: &str = "20";
    pub const MODEL: &str = "21";
    pub const NAME: &str = "23";
    /// The name a controller shows for one service among several alike.
    pub const CONFIGURED_NAME: &str = "E3";
    pub const SERIAL_NUMBER: &str = "30";
    pub const FIRMWARE_REVISION: &str = "52";
    pub const VERSION: &str = "37";
    pub const CURRENT_TEMPERATURE: &str = "11";
    pub const CURRENT_RELATIVE_HUMIDITY: &str = "10";

    pub const MOTION_SENSOR: &str = "85";
    pub const CONTACT_SENSOR: &str = "80";
    pub const LIGHT_SENSOR: &str = "84";
    pub const LEAK_SENSOR: &str = "83";
    pub const OCCUPANCY_SENSOR: &str = "86";
    pub const BATTERY: &str = "96";
    pub const DOORBELL: &str = "121";
    pub const LIGHTBULB: &str = "43";
    pub const MICROPHONE: &str = "112";
    pub const SPEAKER: &str = "113";

    pub const MOTION_DETECTED: &str = "22";
    pub const CONTACT_SENSOR_STATE: &str = "6A";
    pub const CURRENT_AMBIENT_LIGHT_LEVEL: &str = "6B";
    pub const LEAK_DETECTED: &str = "70";
    pub const OCCUPANCY_DETECTED: &str = "71";
    pub const BATTERY_LEVEL: &str = "68";
    pub const CHARGING_STATE: &str = "8F";
    pub const STATUS_LOW_BATTERY: &str = "79";
    pub const STATUS_ACTIVE: &str = "75";
    pub const STATUS_TAMPERED: &str = "7A";
    pub const ON: &str = "25";
    pub const MUTE: &str = "11A";
    pub const BRIGHTNESS: &str = "8";
    pub const PROGRAMMABLE_SWITCH_EVENT: &str = "73";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Bool,
    Uint8,
    Uint16,
    Uint32,
    Int,
    Float,
    String,
    Tlv8,
    Data,
}

impl Format {
    fn name(self) -> &'static str {
        match self {
            Format::Bool => "bool",
            Format::Uint8 => "uint8",
            Format::Uint16 => "uint16",
            Format::Uint32 => "uint32",
            Format::Int => "int",
            Format::Float => "float",
            Format::String => "string",
            Format::Tlv8 => "tlv8",
            Format::Data => "data",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Characteristic {
    pub iid: u64,
    pub kind: &'static str,
    pub format: Format,
    pub readable: bool,
    pub writable: bool,
    pub notifies: bool,
    /// Whether a controller may ask for the handler's answer in the reply
    /// to its write, instead of reading it afterwards.
    pub write_response: bool,
    pub value: Value,
    pub unit: Option<&'static str>,
    /// Minimum, maximum and step for numeric formats.
    pub range: Option<(f64, f64, f64)>,
}

impl Characteristic {
    /// A readable characteristic that also sends change notifications.
    pub fn sensor(kind: &'static str, format: Format, value: Value) -> Self {
        Self { notifies: true, ..Self::constant(kind, format, value) }
    }

    /// A readable characteristic that never changes.
    pub fn constant(kind: &'static str, format: Format, value: Value) -> Self {
        Self {
            iid: 0,
            kind,
            format,
            readable: true,
            writable: false,
            notifies: false,
            write_response: false,
            value,
            unit: None,
            range: None,
        }
    }

    pub fn text(kind: &'static str, value: &str) -> Self {
        Self::constant(kind, Format::String, Value::String(value.to_owned()))
    }

    pub fn unit(mut self, unit: &'static str) -> Self {
        self.unit = Some(unit);
        self
    }

    pub fn range(mut self, min: f64, max: f64, step: f64) -> Self {
        self.range = Some((min, max, step));
        self
    }

    fn perms(&self) -> Vec<&'static str> {
        [(self.readable, "pr"), (self.writable, "pw"), (self.notifies, "ev"), (self.write_response, "wr")]
            .into_iter()
            .filter_map(|(on, name)| on.then_some(name))
            .collect()
    }

    /// The characteristic as it appears in the accessory database.
    pub fn describe(&self) -> Value {
        self.to_json()
    }

    fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("iid".into(), json!(self.iid));
        out.insert("type".into(), json!(self.kind));
        out.insert("format".into(), json!(self.format.name()));
        out.insert("perms".into(), json!(self.perms()));
        if self.readable {
            out.insert("value".into(), self.value.clone());
        }
        if let Some(unit) = self.unit {
            out.insert("unit".into(), json!(unit));
        }
        if let Some((min, max, step)) = self.range {
            // Whole-number formats state their limits as whole numbers;
            // a controller may refuse "100.0" as the limit of an integer.
            let number = |n: f64| match self.format {
                Format::Float => json!(n),
                _ => json!(n as i64),
            };
            out.insert("minValue".into(), number(min));
            out.insert("maxValue".into(), number(max));
            out.insert("minStep".into(), number(step));
        }
        Value::Object(out)
    }

    /// Checks a controller-supplied value against the format and range,
    /// returning it in canonical form.
    fn coerce(&self, value: &Value) -> Option<Value> {
        let in_range = |n: f64| self.range.is_none_or(|(min, max, _)| n >= min && n <= max);
        match self.format {
            Format::Bool => match value {
                Value::Bool(b) => Some(json!(b)),
                Value::Number(n) if n.as_u64() == Some(0) => Some(json!(false)),
                Value::Number(n) if n.as_u64() == Some(1) => Some(json!(true)),
                _ => None,
            },
            Format::Uint8 | Format::Uint16 | Format::Uint32 => {
                let limit = match self.format {
                    Format::Uint8 => u8::MAX as u64,
                    Format::Uint16 => u16::MAX as u64,
                    _ => u32::MAX as u64,
                };
                // Controllers send booleans for some 0/1 integer characteristics.
                let n = value.as_u64().or(value.as_bool().map(u64::from))?;
                (n <= limit && in_range(n as f64)).then(|| json!(n))
            }
            Format::Int => {
                let n = value.as_i64()?;
                (i32::try_from(n).is_ok() && in_range(n as f64)).then(|| json!(n))
            }
            Format::Float => value.as_f64().filter(|n| n.is_finite() && in_range(*n)).map(|n| json!(n)),
            Format::String | Format::Tlv8 | Format::Data => value.is_string().then(|| value.clone()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Service {
    pub iid: u64,
    pub kind: &'static str,
    pub primary: bool,
    /// Instance ids of services this one works together with.
    pub linked: Vec<u64>,
    pub characteristics: Vec<Characteristic>,
}

/// Identity shown in the Home app's accessory details.
pub struct Info<'a> {
    pub name: &'a str,
    pub manufacturer: &'a str,
    pub model: &'a str,
    pub serial_number: &'a str,
    pub firmware_revision: &'a str,
}

#[derive(Clone, Debug)]
pub struct Accessory {
    pub aid: u64,
    pub services: Vec<Service>,
    next_iid: u64,
}

impl Accessory {
    /// Creates an accessory with its mandatory information service.
    ///
    /// Instance ids are assigned in the order services are added, so an
    /// accessory must always be built in the same order to keep them stable.
    pub fn new(aid: u64, info: &Info) -> Self {
        let mut accessory = Self { aid, services: Vec::new(), next_iid: 1 };
        accessory.add_service(
            kind::ACCESSORY_INFORMATION,
            false,
            vec![
                Characteristic {
                    readable: false,
                    writable: true,
                    ..Characteristic::constant(kind::IDENTIFY, Format::Bool, Value::Null)
                },
                Characteristic::text(kind::MANUFACTURER, info.manufacturer),
                Characteristic::text(kind::MODEL, info.model),
                Characteristic::text(kind::NAME, info.name),
                Characteristic::text(kind::SERIAL_NUMBER, info.serial_number),
                Characteristic::text(kind::FIRMWARE_REVISION, info.firmware_revision),
            ],
        );
        accessory
    }

    /// Adds a service and returns the instance ids of its characteristics,
    /// in the order given.
    pub fn add_service(
        &mut self,
        kind: &'static str,
        primary: bool,
        characteristics: Vec<Characteristic>,
    ) -> Vec<u64> {
        let iid = self.next_iid;
        self.next_iid += 1;
        let characteristics: Vec<Characteristic> = characteristics
            .into_iter()
            .map(|c| {
                let iid = self.next_iid;
                self.next_iid += 1;
                Characteristic { iid, ..c }
            })
            .collect();
        let ids = characteristics.iter().map(|c| c.iid).collect();
        self.services.push(Service { iid, kind, primary, linked: Vec::new(), characteristics });
        ids
    }

    /// Adds a service at a fixed instance id, with its characteristics
    /// numbered consecutively after it.
    ///
    /// HomeKit remembers accessories by instance id, so optional services
    /// should each get a reserved id. That way enabling or disabling one
    /// never renumbers the others.
    pub fn add_service_at(
        &mut self,
        iid: u64,
        kind: &'static str,
        primary: bool,
        characteristics: Vec<Characteristic>,
    ) -> Vec<u64> {
        let end = iid + characteristics.len() as u64;
        let in_use = |id: u64| {
            self.services.iter().any(|s| s.iid == id || s.characteristics.iter().any(|c| c.iid == id))
        };
        assert!(!(iid..=end).any(in_use), "instance ids {iid}..={end} overlap an existing service");
        let restore = self.next_iid;
        self.next_iid = iid;
        let ids = self.add_service(kind, primary, characteristics);
        self.next_iid = restore.max(end + 1);
        ids
    }

    /// Records that the service at `from` works together with the one at
    /// `to`. Both are service instance ids.
    pub fn link(&mut self, from: u64, to: u64) {
        if let Some(service) = self.services.iter_mut().find(|s| s.iid == from) {
            service.linked.push(to);
        }
    }

    fn characteristic(&self, iid: u64) -> Option<&Characteristic> {
        self.services.iter().flat_map(|s| &s.characteristics).find(|c| c.iid == iid)
    }

    fn characteristic_mut(&mut self, iid: u64) -> Option<&mut Characteristic> {
        self.services.iter_mut().flat_map(|s| &mut s.characteristics).find(|c| c.iid == iid)
    }
}

/// A characteristic value change.
#[derive(Clone, Debug)]
pub struct Change {
    pub aid: u64,
    pub iid: u64,
    pub value: Value,
    /// Connection that caused the change, which must not be notified of it.
    pub origin: Option<u64>,
}

/// Who is writing, for handlers that need to answer the same controller.
#[derive(Clone, Copy, Debug)]
pub struct WriteContext {
    /// Identifies the controller connection for the life of that connection.
    pub connection: u64,
    /// This machine's address as the controller reached it.
    pub local_ip: IpAddr,
    pub peer_ip: IpAddr,
    /// The secret this controller's encrypted session is built on, from
    /// which keys for side channels are derived.
    pub shared_secret: Option<[u8; 32]>,
}

/// Runs synchronously when a controller writes a characteristic. Returning
/// `Ok(Some(value))` stores that value instead of the one written, which is
/// how request-and-response characteristics hand back their answer.
pub type WriteHandler = Arc<dyn Fn(&Value, &WriteContext) -> Result<Option<Value>, i32> + Send + Sync>;

pub struct Database {
    accessories: RwLock<Vec<Accessory>>,
    handlers: RwLock<HashMap<(u64, u64), WriteHandler>>,
    changes: broadcast::Sender<Change>,
    writes: broadcast::Sender<Change>,
    closed: broadcast::Sender<u64>,
}

impl Database {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            accessories: RwLock::new(Vec::new()),
            handlers: RwLock::new(HashMap::new()),
            changes: broadcast::channel(1024).0,
            writes: broadcast::channel(256).0,
            closed: broadcast::channel(64).0,
        })
    }

    pub fn add(&self, accessory: Accessory) {
        self.accessories.write().unwrap().push(accessory);
    }

    /// Swaps in a rebuilt accessory with the same id, or adds it if new.
    /// Write handlers for the old one are dropped.
    pub fn replace(&self, accessory: Accessory) {
        self.handlers.write().unwrap().retain(|(aid, _), _| *aid != accessory.aid);
        let mut accessories = self.accessories.write().unwrap();
        match accessories.iter_mut().find(|a| a.aid == accessory.aid) {
            Some(existing) => *existing = accessory,
            None => accessories.push(accessory),
        }
    }

    /// Takes an accessory out of the database, with its write handlers.
    /// Returns whether it was there.
    pub fn remove(&self, aid: u64) -> bool {
        self.handlers.write().unwrap().retain(|(owner, _), _| *owner != aid);
        let mut accessories = self.accessories.write().unwrap();
        let before = accessories.len();
        accessories.retain(|a| a.aid != aid);
        accessories.len() != before
    }

    /// Registers the handler for writes to one characteristic.
    pub fn on_write(&self, aid: u64, iid: u64, handler: WriteHandler) {
        self.handlers.write().unwrap().insert((aid, iid), handler);
    }

    /// Announces that a controller connection has ended, so anything started
    /// on its behalf can be stopped.
    pub fn connection_closed(&self, connection: u64) {
        let _ = self.closed.send(connection);
    }

    pub fn subscribe_connection_closed(&self) -> broadcast::Receiver<u64> {
        self.closed.subscribe()
    }

    /// Every value change, for delivering events to subscribed controllers.
    pub fn subscribe_changes(&self) -> broadcast::Receiver<Change> {
        self.changes.subscribe()
    }

    /// Values written by controllers, for integrations to act on.
    pub fn subscribe_writes(&self) -> broadcast::Receiver<Change> {
        self.writes.subscribe()
    }

    pub fn to_json(&self) -> Value {
        let accessories: Vec<Value> = self
            .accessories
            .read()
            .unwrap()
            .iter()
            .map(|a| {
                let services: Vec<Value> = a
                    .services
                    .iter()
                    .map(|s| {
                        let chars: Vec<Value> = s.characteristics.iter().map(|c| c.to_json()).collect();
                        let mut service = json!({ "iid": s.iid, "type": s.kind, "characteristics": chars });
                        if s.primary {
                            service["primary"] = json!(true);
                        }
                        if !s.linked.is_empty() {
                            service["linked"] = json!(s.linked);
                        }
                        service
                    })
                    .collect();
                json!({ "aid": a.aid, "services": services })
            })
            .collect();
        json!({ "accessories": accessories })
    }

    /// A digest of the database's shape: which accessories, services and
    /// characteristics exist, ignoring their values. If this differs from
    /// the last run, controllers must be told to re-read the database.
    pub fn layout(&self) -> String {
        let mut shape = String::new();
        for a in self.accessories.read().unwrap().iter() {
            shape.push_str(&format!("a{}", a.aid));
            for s in &a.services {
                shape.push_str(&format!("s{}:{}:{:?}", s.iid, s.kind, s.linked));
                for c in &s.characteristics {
                    // Format and limits are part of what a controller remembers.
                    shape.push_str(&format!("c{}:{}:{}:{:?}", c.iid, c.kind, c.format.name(), c.range));
                    // Fixed structured values, such as the codecs a camera
                    // offers, are part of what a controller remembers.
                    if matches!(c.format, Format::Tlv8) && !c.writable && !c.notifies {
                        shape.push_str(&format!("={}", c.value));
                    }
                }
            }
        }
        crate::crypto::to_hex(&<sha2::Sha256 as sha2::Digest>::digest(shape.as_bytes()))
    }

    /// Runs `f` on a characteristic, or returns `None` if it does not exist.
    pub fn with<T>(&self, aid: u64, iid: u64, f: impl FnOnce(&Characteristic) -> T) -> Option<T> {
        let accessories = self.accessories.read().unwrap();
        accessories.iter().find(|a| a.aid == aid)?.characteristic(iid).map(f)
    }

    /// Reads a value on behalf of a controller.
    pub fn read(&self, aid: u64, iid: u64) -> Result<Value, i32> {
        self.with(aid, iid, |c| if c.readable { Ok(c.value.clone()) } else { Err(status::WRITE_ONLY) })
            .unwrap_or(Err(status::NOT_FOUND))
    }

    /// Applies a write from a controller connection.
    /// Applies a controller's write and returns the value that was stored:
    /// what was written, or the handler's answer.
    pub fn write(&self, aid: u64, iid: u64, value: &Value, context: &WriteContext) -> Result<Value, i32> {
        let value = self
            .with(aid, iid, |c| {
                if !c.writable {
                    return Err(status::READ_ONLY);
                }
                c.coerce(value).ok_or(status::INVALID_VALUE)
            })
            .unwrap_or(Err(status::NOT_FOUND))?;
        // The handler runs outside the lock so it can read and set other values.
        let handler = self.handlers.read().unwrap().get(&(aid, iid)).cloned();
        let stored = match handler {
            Some(handler) => handler(&value, context)?.unwrap_or(value),
            None => value,
        };
        let change = {
            let mut accessories = self.accessories.write().unwrap();
            let c = accessories
                .iter_mut()
                .find(|a| a.aid == aid)
                .and_then(|a| a.characteristic_mut(iid))
                .ok_or(status::NOT_FOUND)?;
            // Write-only characteristics such as Identify hold no state.
            if c.readable {
                c.value = stored.clone();
            }
            Change { aid, iid, value: stored.clone(), origin: Some(context.connection) }
        };
        // Send errors only mean nobody is listening.
        let _ = self.writes.send(change.clone());
        let _ = self.changes.send(change);
        Ok(stored)
    }

    /// Sends an event without storing a value, for stateless things such as
    /// a doorbell press where every occurrence matters even if it repeats.
    pub fn emit(&self, aid: u64, iid: u64, value: Value) {
        let _ = self.changes.send(Change { aid, iid, value, origin: None });
    }

    /// Whether an accessory with this id has been added.
    pub fn contains(&self, aid: u64) -> bool {
        self.accessories.read().unwrap().iter().any(|a| a.aid == aid)
    }

    /// Updates a value from an integration. Returns `false` if the
    /// characteristic does not exist. Unchanged values send no event.
    pub fn set(&self, aid: u64, iid: u64, value: Value) -> bool {
        let mut accessories = self.accessories.write().unwrap();
        let Some(c) = accessories.iter_mut().find(|a| a.aid == aid).and_then(|a| a.characteristic_mut(iid))
        else {
            return false;
        };
        if c.value != value {
            c.value = value.clone();
            let _ = self.changes.send(Change { aid, iid, value, origin: None });
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Arc<Database>, u64) {
        let info = Info {
            name: "Porch",
            manufacturer: "Test",
            model: "T1",
            serial_number: "1",
            firmware_revision: "1.0",
        };
        let mut accessory = Accessory::new(2, &info);
        let ids = accessory.add_service(
            kind::TEMPERATURE_SENSOR,
            true,
            vec![Characteristic::sensor(kind::CURRENT_TEMPERATURE, Format::Float, json!(20.0))
                .unit("celsius")
                .range(-100.0, 100.0, 0.1)],
        );
        let db = Database::new();
        db.add(accessory);
        (db, ids[0])
    }

    fn context() -> WriteContext {
        WriteContext {
            connection: 1,
            local_ip: "10.0.0.2".parse().unwrap(),
            peer_ip: "10.0.0.9".parse().unwrap(),
            shared_secret: None,
        }
    }

    #[test]
    fn write_handlers_can_answer_reject_and_are_dropped_on_replace() {
        let info = Info { name: "n", manufacturer: "m", model: "m", serial_number: "s", firmware_revision: "1" };
        let build = || {
            let mut accessory = Accessory::new(2, &info);
            let ids = accessory.add_service_at(
                100,
                "110",
                true,
                vec![Characteristic { writable: true, ..Characteristic::constant("118", Format::Tlv8, json!("")) }],
            );
            (accessory, ids[0])
        };
        let db = Database::new();
        let (accessory, iid) = build();
        db.add(accessory);
        db.on_write(
            2,
            iid,
            Arc::new(|value, ctx| match value.as_str() {
                Some("ask") => Ok(Some(json!(format!("answer for {}", ctx.peer_ip)))),
                Some("bad") => Err(status::INVALID_VALUE),
                _ => Ok(None),
            }),
        );
        assert_eq!(db.write(2, iid, &json!("ask"), &context()), Ok(json!("answer for 10.0.0.9")));
        assert_eq!(db.read(2, iid), Ok(json!("answer for 10.0.0.9")));
        assert_eq!(db.write(2, iid, &json!("bad"), &context()), Err(status::INVALID_VALUE));
        assert_eq!(db.read(2, iid), Ok(json!("answer for 10.0.0.9")), "a rejected write stores nothing");
        assert_eq!(db.write(2, iid, &json!("plain"), &context()), Ok(json!("plain")));
        assert_eq!(db.read(2, iid), Ok(json!("plain")));

        let (accessory, iid) = build();
        db.replace(accessory);
        assert_eq!(db.write(2, iid, &json!("ask"), &context()), Ok(json!("ask")));
        assert_eq!(db.read(2, iid), Ok(json!("ask")), "the old handler is gone");
        assert_eq!(db.to_json()["accessories"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn removing_an_accessory_drops_it_and_its_handlers() {
        let (db, iid) = sample();
        db.on_write(2, iid, Arc::new(|_, _| Ok(None)));
        assert!(db.remove(2));
        assert!(!db.contains(2) && !db.remove(2));
        assert_eq!(db.read(2, iid), Err(status::NOT_FOUND));
        assert!(db.handlers.read().unwrap().is_empty());
    }

    #[test]
    fn instance_ids_are_sequential_and_unique() {
        let (db, temperature) = sample();
        // Information service is iid 1 with six characteristics (2..=7),
        // then the sensor service is 8 and its characteristic 9.
        assert_eq!(temperature, 9);
        let json = db.to_json();
        assert_eq!(json["accessories"][0]["services"][1]["iid"], 8);
        assert_eq!(json["accessories"][0]["services"][0]["characteristics"][0]["perms"], json!(["pw"]));
        assert!(json["accessories"][0]["services"][0]["characteristics"][0].get("value").is_none());
    }

    #[test]
    fn fixed_instance_ids_stay_put_and_overlaps_panic() {
        let info = Info { name: "n", manufacturer: "m", model: "m", serial_number: "s", firmware_revision: "1" };
        let mut accessory = Accessory::new(2, &info);
        let motion = accessory.add_service_at(
            100,
            kind::MOTION_SENSOR,
            true,
            vec![Characteristic::sensor(kind::MOTION_DETECTED, Format::Bool, json!(false))],
        );
        assert_eq!(motion, vec![101]);
        // Sequential allocation continues after the reserved block.
        let next = accessory.add_service(kind::BATTERY, false, vec![Characteristic::sensor(kind::BATTERY_LEVEL, Format::Uint8, json!(50))]);
        assert_eq!(next, vec![103]);
        let overlap = std::panic::catch_unwind(move || {
            accessory.add_service_at(101, kind::LEAK_SENSOR, false, vec![]);
        });
        assert!(overlap.is_err());
    }

    #[test]
    fn emit_always_notifies_and_stores_nothing() {
        let (db, iid) = sample();
        let mut changes = db.subscribe_changes();
        db.emit(2, iid, json!(0));
        db.emit(2, iid, json!(0));
        assert_eq!(changes.try_recv().unwrap().value, json!(0));
        assert_eq!(changes.try_recv().unwrap().value, json!(0));
        assert_eq!(db.read(2, iid), Ok(json!(20.0)));
        assert!(db.contains(2) && !db.contains(3));
    }

    #[test]
    fn layout_ignores_values_but_sees_structure() {
        let (db, iid) = sample();
        let before = db.layout();
        db.set(2, iid, json!(30.0));
        assert_eq!(db.layout(), before);
        let info = Info { name: "n", manufacturer: "m", model: "m", serial_number: "s", firmware_revision: "1" };
        db.add(Accessory::new(3, &info));
        assert_ne!(db.layout(), before);
    }

    #[test]
    fn set_notifies_only_on_change() {
        let (db, iid) = sample();
        let mut changes = db.subscribe_changes();
        assert!(db.set(2, iid, json!(20.0)));
        assert!(changes.try_recv().is_err());
        assert!(db.set(2, iid, json!(21.5)));
        assert_eq!(changes.try_recv().unwrap().value, json!(21.5));
        assert!(!db.set(2, 99, json!(1)));
    }

    #[test]
    fn controller_access_is_checked() {
        let (db, iid) = sample();
        assert_eq!(db.read(2, iid), Ok(json!(20.0)));
        assert_eq!(db.read(2, 2), Err(status::WRITE_ONLY));
        assert_eq!(db.read(9, 1), Err(status::NOT_FOUND));
        assert!(!db.remove(9), "nothing to remove");
        let ctx = context();
        assert_eq!(db.write(2, iid, &json!(5.0), &ctx), Err(status::READ_ONLY));
        assert_eq!(db.write(2, 2, &json!(1), &ctx), Ok(json!(true)));
        assert_eq!(db.write(2, 2, &json!("x"), &ctx), Err(status::INVALID_VALUE));
    }
}
