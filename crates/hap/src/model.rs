//! The accessory database: accessories, their services and characteristics,
//! and the change notifications that drive HomeKit events.

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
    pub const SERIAL_NUMBER: &str = "30";
    pub const FIRMWARE_REVISION: &str = "52";
    pub const VERSION: &str = "37";
    pub const CURRENT_TEMPERATURE: &str = "11";
    pub const CURRENT_RELATIVE_HUMIDITY: &str = "10";
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
        [(self.readable, "pr"), (self.writable, "pw"), (self.notifies, "ev")]
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
            out.insert("minValue".into(), json!(min));
            out.insert("maxValue".into(), json!(max));
            out.insert("minStep".into(), json!(step));
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
        self.services.push(Service { iid, kind, primary, characteristics });
        ids
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

pub struct Database {
    accessories: RwLock<Vec<Accessory>>,
    changes: broadcast::Sender<Change>,
    writes: broadcast::Sender<Change>,
}

impl Database {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            accessories: RwLock::new(Vec::new()),
            changes: broadcast::channel(1024).0,
            writes: broadcast::channel(256).0,
        })
    }

    pub fn add(&self, accessory: Accessory) {
        self.accessories.write().unwrap().push(accessory);
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
                        service
                    })
                    .collect();
                json!({ "aid": a.aid, "services": services })
            })
            .collect();
        json!({ "accessories": accessories })
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
    pub fn write(&self, aid: u64, iid: u64, value: &Value, origin: u64) -> Result<(), i32> {
        let change = {
            let mut accessories = self.accessories.write().unwrap();
            let c = accessories
                .iter_mut()
                .find(|a| a.aid == aid)
                .and_then(|a| a.characteristic_mut(iid))
                .ok_or(status::NOT_FOUND)?;
            if !c.writable {
                return Err(status::READ_ONLY);
            }
            let value = c.coerce(value).ok_or(status::INVALID_VALUE)?;
            // Write-only characteristics such as Identify hold no state.
            if c.readable {
                c.value = value.clone();
            }
            Change { aid, iid, value, origin: Some(origin) }
        };
        // Send errors only mean nobody is listening.
        let _ = self.writes.send(change.clone());
        let _ = self.changes.send(change);
        Ok(())
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
        assert_eq!(db.write(2, iid, &json!(5.0), 1), Err(status::READ_ONLY));
        assert_eq!(db.write(2, 2, &json!(1), 1), Ok(()));
        assert_eq!(db.write(2, 2, &json!("x"), 1), Err(status::INVALID_VALUE));
    }
}
