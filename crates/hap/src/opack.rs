//! The compact binary encoding HomeKit data streams use for their messages
//! (Apple calls it OPACK). Values are tagged by a leading byte; small
//! integers, short strings and short lists fit their size into the tag.

/// Nesting deeper than this is refused, so a hostile message cannot
/// exhaust the stack.
const MAX_DEPTH: usize = 16;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Encoded in the fewest bytes that hold it.
    Int(i64),
    /// Always encoded as eight bytes, which is how message ids and status
    /// codes are expected.
    Wide(i64),
    Float(f64),
    Str(String),
    Data(Vec<u8>),
    Array(Vec<Value>),
    /// Key order is kept, since it is part of what is sent.
    Dict(Vec<(Value, Value)>),
}

impl Value {
    /// A dictionary with text keys.
    pub fn dict<const N: usize>(entries: [(&str, Value); N]) -> Self {
        Self::Dict(entries.into_iter().map(|(k, v)| (Value::Str(k.to_owned()), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Dict(entries) => entries.iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(n) | Self::Wide(n) => Some(*n),
            _ => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.push(0x04),
            Self::Bool(true) => out.push(0x01),
            Self::Bool(false) => out.push(0x02),
            Self::Int(n) => match *n {
                -1 => out.push(0x07),
                0..=39 => out.push(0x08 + *n as u8),
                n if i8::try_from(n).is_ok() => {
                    out.push(0x30);
                    out.extend_from_slice(&(n as i8).to_le_bytes());
                }
                n if i16::try_from(n).is_ok() => {
                    out.push(0x31);
                    out.extend_from_slice(&(n as i16).to_le_bytes());
                }
                n if i32::try_from(n).is_ok() => {
                    out.push(0x32);
                    out.extend_from_slice(&(n as i32).to_le_bytes());
                }
                n => Self::Wide(n).write(out),
            },
            Self::Wide(n) => {
                out.push(0x33);
                out.extend_from_slice(&n.to_le_bytes());
            }
            Self::Float(f) => {
                out.push(0x36);
                out.extend_from_slice(&f.to_le_bytes());
            }
            Self::Str(s) => {
                write_length(out, 0x40, s.len());
                out.extend_from_slice(s.as_bytes());
            }
            Self::Data(d) => {
                write_length(out, 0x70, d.len());
                out.extend_from_slice(d);
            }
            Self::Array(items) => {
                let counted = items.len() <= 12;
                out.push(if counted { 0xD0 + items.len() as u8 } else { 0xDF });
                items.iter().for_each(|v| v.write(out));
                if !counted {
                    out.push(0x03);
                }
            }
            Self::Dict(entries) => {
                let counted = entries.len() <= 14;
                out.push(if counted { 0xE0 + entries.len() as u8 } else { 0xEF });
                for (key, value) in entries {
                    key.write(out);
                    value.write(out);
                }
                if !counted {
                    out.push(0x03);
                }
            }
        }
    }

    /// Decodes one value that must fill `bytes` exactly.
    pub fn decode(bytes: &[u8]) -> Option<Value> {
        let mut reader = Reader { rest: bytes, seen: Vec::new() };
        let value = reader.value(0)?;
        (reader.rest.is_empty() && value != Item::End).then_some(())?;
        match value {
            Item::Value(v) => Some(v),
            Item::End => None,
        }
    }
}

/// Strings and data share a scheme: lengths up to 32 sit in the tag, longer
/// ones follow it in one, two or four bytes.
fn write_length(out: &mut Vec<u8>, base: u8, len: usize) {
    if len <= 32 {
        out.push(base + len as u8);
    } else if let Ok(n) = u8::try_from(len) {
        out.extend_from_slice(&[base + 0x21, n]);
    } else if let Ok(n) = u16::try_from(len) {
        out.push(base + 0x22);
        out.extend_from_slice(&n.to_le_bytes());
    } else {
        out.push(base + 0x23);
        out.extend_from_slice(&(len as u32).to_le_bytes());
    }
}

#[derive(PartialEq)]
enum Item {
    Value(Value),
    /// The marker that ends an uncounted list.
    End,
}

struct Reader<'a> {
    rest: &'a [u8],
    /// Values a later tag may refer back to instead of repeating them.
    seen: Vec<Value>,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let (head, tail) = self.rest.split_at_checked(n)?;
        self.rest = tail;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn length(&mut self, width: u8) -> Option<usize> {
        Some(match width {
            1 => self.array::<1>()?[0] as usize,
            2 => u16::from_le_bytes(self.array()?) as usize,
            3 => u32::from_le_bytes(self.array()?) as usize,
            _ => usize::try_from(u64::from_le_bytes(self.array()?)).ok()?,
        })
    }

    fn track(&mut self, value: Value) -> Option<Item> {
        self.seen.push(value.clone());
        Some(Item::Value(value))
    }

    fn text(&mut self, len: usize) -> Option<Item> {
        let text = std::str::from_utf8(self.take(len)?).ok()?.to_owned();
        if len == 0 {
            return Some(Item::Value(Value::Str(text)));
        }
        self.track(Value::Str(text))
    }

    fn data(&mut self, len: usize) -> Option<Item> {
        let data = self.take(len)?.to_vec();
        if len == 0 {
            return Some(Item::Value(Value::Data(data)));
        }
        self.track(Value::Data(data))
    }

    fn value(&mut self, depth: usize) -> Option<Item> {
        if depth > MAX_DEPTH {
            return None;
        }
        let tag = self.array::<1>()?[0];
        let plain = |v| Some(Item::Value(v));
        match tag {
            0x01 => plain(Value::Bool(true)),
            0x02 => plain(Value::Bool(false)),
            0x03 => Some(Item::End),
            0x04 => plain(Value::Null),
            // A UUID, kept as its sixteen bytes.
            0x05 => {
                let bytes = self.take(16)?.to_vec();
                self.track(Value::Data(bytes))
            }
            // A date, as seconds since 2001.
            0x06 => plain(Value::Float(f64::from_le_bytes(self.array()?))),
            0x07 => plain(Value::Int(-1)),
            0x08..=0x2F => plain(Value::Int((tag - 0x08) as i64)),
            0x30 => {
                let n = i8::from_le_bytes(self.array()?);
                self.track(Value::Int(n as i64))
            }
            0x31 => {
                let n = i16::from_le_bytes(self.array()?);
                self.track(Value::Int(n as i64))
            }
            0x32 => {
                let n = i32::from_le_bytes(self.array()?);
                self.track(Value::Int(n as i64))
            }
            0x33 => {
                let n = i64::from_le_bytes(self.array()?);
                self.track(Value::Int(n))
            }
            0x35 => {
                let f = f32::from_le_bytes(self.array()?);
                self.track(Value::Float(f as f64))
            }
            0x36 => {
                let f = f64::from_le_bytes(self.array()?);
                self.track(Value::Float(f))
            }
            0x40..=0x60 => self.text((tag - 0x40) as usize),
            0x61..=0x64 => {
                let len = self.length(tag - 0x60)?;
                self.text(len)
            }
            // Text that runs to a zero byte.
            0x6F => {
                let len = self.rest.iter().position(|b| *b == 0)?;
                let item = self.text(len)?;
                self.take(1)?;
                Some(item)
            }
            0x70..=0x90 => self.data((tag - 0x70) as usize),
            0x91..=0x94 => {
                let len = self.length(tag - 0x90)?;
                self.data(len)
            }
            0xA0..=0xCF => plain(self.seen.get((tag - 0xA0) as usize)?.clone()),
            0xD0..=0xDE => {
                let mut items = Vec::new();
                for _ in 0..tag - 0xD0 {
                    match self.value(depth + 1)? {
                        Item::Value(v) => items.push(v),
                        Item::End => return None,
                    }
                }
                plain(Value::Array(items))
            }
            0xDF => {
                let mut items = Vec::new();
                while let Item::Value(v) = self.value(depth + 1)? {
                    items.push(v);
                }
                plain(Value::Array(items))
            }
            0xE0..=0xEE => {
                let mut entries = Vec::new();
                for _ in 0..tag - 0xE0 {
                    let (Item::Value(k), Item::Value(v)) = (self.value(depth + 1)?, self.value(depth + 1)?) else {
                        return None;
                    };
                    entries.push((k, v));
                }
                plain(Value::Dict(entries))
            }
            0xEF => {
                let mut entries = Vec::new();
                while let Item::Value(k) = self.value(depth + 1)? {
                    let Item::Value(v) = self.value(depth + 1)? else { return None };
                    entries.push((k, v));
                }
                plain(Value::Dict(entries))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(value: Value) -> Vec<u8> {
        let bytes = value.encode();
        let expected = match &value {
            Value::Wide(n) => Value::Int(*n),
            other => other.clone(),
        };
        assert_eq!(Value::decode(&bytes), Some(expected), "{bytes:02x?}");
        bytes
    }

    #[test]
    fn encodes_each_kind_in_its_documented_form() {
        assert_eq!(round_trip(Value::Null), [0x04]);
        assert_eq!(round_trip(Value::Bool(true)), [0x01]);
        assert_eq!(round_trip(Value::Bool(false)), [0x02]);
        assert_eq!(round_trip(Value::Int(-1)), [0x07]);
        assert_eq!(round_trip(Value::Int(0)), [0x08]);
        assert_eq!(round_trip(Value::Int(39)), [0x2F]);
        assert_eq!(round_trip(Value::Int(40)), [0x30, 40]);
        assert_eq!(round_trip(Value::Int(-2)), [0x30, 0xFE]);
        assert_eq!(round_trip(Value::Int(300)), [0x31, 0x2C, 0x01]);
        assert_eq!(round_trip(Value::Int(70_000)), [0x32, 0x70, 0x11, 0x01, 0x00]);
        assert_eq!(round_trip(Value::Int(1 << 40)).len(), 9);
        assert_eq!(round_trip(Value::Wide(5)), [0x33, 5, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(round_trip(Value::Float(1.5))[0], 0x36);
        assert_eq!(round_trip(Value::Str(String::new())), [0x40]);
        assert_eq!(round_trip(Value::Str("hi".into())), [0x42, b'h', b'i']);
        assert_eq!(round_trip(Value::Str("x".repeat(33)))[..2], [0x61, 33]);
        assert_eq!(round_trip(Value::Data(vec![9; 3])), [0x73, 9, 9, 9]);
        assert_eq!(round_trip(Value::Data(vec![0; 300]))[..3], [0x92, 0x2C, 0x01]);
        assert_eq!(round_trip(Value::Data(vec![0; 70_000]))[..5], [0x93, 0x70, 0x11, 0x01, 0x00]);
        assert_eq!(round_trip(Value::Array(vec![Value::Int(1), Value::Bool(true)])), [0xD2, 0x09, 0x01]);
        let long = round_trip(Value::Array(vec![Value::Int(1); 13]));
        assert_eq!((long[0], long[14]), (0xDF, 0x03));
        assert_eq!(round_trip(Value::dict([("a", Value::Int(2))])), [0xE1, 0x41, b'a', 0x0A]);
        let entries: Vec<_> = (0..15).map(|n| (Value::Int(n), Value::Int(n))).collect();
        let big = round_trip(Value::Dict(entries));
        assert_eq!((big[0], *big.last().unwrap()), (0xEF, 0x03));
    }

    #[test]
    fn reads_fields_out_of_a_dictionary() {
        let message = Value::dict([("streamId", Value::Int(7)), ("type", Value::Str("ipcamera.recording".into()))]);
        let decoded = Value::decode(&message.encode()).unwrap();
        assert_eq!(decoded.get("streamId").and_then(Value::as_i64), Some(7));
        assert_eq!(decoded.get("type").and_then(Value::as_str), Some("ipcamera.recording"));
        assert_eq!(decoded.get("missing"), None);
    }

    #[test]
    fn follows_references_to_earlier_values() {
        // ["dataSend", <the first tracked value again>, 300, <the second>]
        let mut bytes = vec![0xD4, 0x48];
        bytes.extend_from_slice(b"dataSend");
        bytes.extend_from_slice(&[0xA0, 0x31, 0x2C, 0x01, 0xA1]);
        let text = Value::Str("dataSend".into());
        assert_eq!(
            Value::decode(&bytes),
            Some(Value::Array(vec![text.clone(), text, Value::Int(300), Value::Int(300)]))
        );
        // A reference to something not yet seen.
        assert_eq!(Value::decode(&[0xD1, 0xA0]), None);
    }

    #[test]
    fn reads_other_forms_a_controller_may_send() {
        assert_eq!(Value::decode(&[0x6F, b'o', b'k', 0]), Some(Value::Str("ok".into())));
        let mut uuid = vec![0x05];
        uuid.extend_from_slice(&[7; 16]);
        assert_eq!(Value::decode(&uuid), Some(Value::Data(vec![7; 16])));
        let mut date = vec![0x06];
        date.extend_from_slice(&2.0f64.to_le_bytes());
        assert_eq!(Value::decode(&date), Some(Value::Float(2.0)));
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            &[][..],
            &[0x00],
            &[0x03],
            &[0x42, b'h'],
            &[0x41, 0xFF],
            &[0x31, 0x01],
            &[0x93, 0xFF, 0xFF, 0xFF, 0xFF],
            &[0xD2, 0x08],
            &[0xE1, 0x41, b'a'],
            &[0xDF, 0x08],
            &[0xEF, 0x41, b'a', 0x03],
            &[0x08, 0x08],
        ] {
            assert_eq!(Value::decode(bad), None, "{bad:02x?}");
        }
        // Lists nested too deeply.
        let mut deep = vec![0xD1; MAX_DEPTH + 2];
        deep.push(0x08);
        assert_eq!(Value::decode(&deep), None);
    }
}
