//! Protect's realtime update stream.
//!
//! Each WebSocket message carries two frames back to back: an *action*
//! frame saying what changed (which kind of object, which id, add, update
//! or remove) and a *data* frame with the changed fields. Every frame has
//! an 8-byte header and an optionally zlib-compressed payload.

use std::io::Read;

use futures_util::StreamExt;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// Largest payload accepted after decompression. Real updates are a few
/// kilobytes; this stops a hostile or corrupt frame from exhausting memory.
const MAX_PAYLOAD: u64 = 16 * 1024 * 1024;
const HEADER_LEN: usize = 8;

const FRAME_ACTION: u8 = 1;
const FRAME_DATA: u8 = 2;
const FORMAT_JSON: u8 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("update packet is truncated")]
    Truncated,
    #[error("unexpected frame type {0}")]
    FrameType(u8),
    #[error("could not decompress frame")]
    Compression,
    #[error("frame is larger than the {MAX_PAYLOAD} byte limit")]
    TooLarge,
    #[error("frame is not valid JSON: {0}")]
    Json(String),
}

/// One change reported by the console.
#[derive(Clone, Debug, PartialEq)]
pub struct Update {
    /// `add`, `update` or `remove`.
    pub action: String,
    /// The kind of object that changed: `camera`, `event`, `sensor`, ...
    pub model_key: String,
    pub id: String,
    /// Passed back when reconnecting so no updates are missed.
    pub new_update_id: Option<String>,
    /// The changed fields. Not JSON for a few binary-only updates, in which
    /// case this is `Null`.
    pub data: Value,
}

struct Frame<'a> {
    kind: u8,
    format: u8,
    payload: Vec<u8>,
    rest: &'a [u8],
}

fn read_frame(bytes: &[u8]) -> Result<Frame<'_>, DecodeError> {
    let header = bytes.get(..HEADER_LEN).ok_or(DecodeError::Truncated)?;
    let (kind, format, deflated) = (header[0], header[1], header[2] != 0);
    let size = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let body = bytes.get(HEADER_LEN..HEADER_LEN + size).ok_or(DecodeError::Truncated)?;
    let payload = if deflated {
        let mut out = Vec::new();
        // Read one byte past the limit so an oversized frame is detectable.
        flate2::read::ZlibDecoder::new(body)
            .take(MAX_PAYLOAD + 1)
            .read_to_end(&mut out)
            .map_err(|_| DecodeError::Compression)?;
        if out.len() as u64 > MAX_PAYLOAD {
            return Err(DecodeError::TooLarge);
        }
        out
    } else {
        body.to_vec()
    };
    Ok(Frame { kind, format, payload, rest: &bytes[HEADER_LEN + size..] })
}

/// Decodes one WebSocket message from the update stream.
pub fn decode_packet(bytes: &[u8]) -> Result<Update, DecodeError> {
    let action = read_frame(bytes)?;
    if action.kind != FRAME_ACTION {
        return Err(DecodeError::FrameType(action.kind));
    }
    let data = read_frame(action.rest)?;
    if data.kind != FRAME_DATA {
        return Err(DecodeError::FrameType(data.kind));
    }
    let header: Value =
        serde_json::from_slice(&action.payload).map_err(|e| DecodeError::Json(e.to_string()))?;
    let text = |key: &str| header[key].as_str().unwrap_or_default().to_owned();
    Ok(Update {
        action: text("action"),
        model_key: text("modelKey"),
        id: text("id"),
        new_update_id: header["newUpdateId"].as_str().map(str::to_owned),
        data: if data.format == FORMAT_JSON {
            serde_json::from_slice(&data.payload).map_err(|e| DecodeError::Json(e.to_string()))?
        } else {
            Value::Null
        },
    })
}

/// A live connection to the update stream.
pub struct UpdateStream {
    socket: WebSocketStream<TlsStream<TcpStream>>,
}

impl UpdateStream {
    pub(crate) fn new(socket: WebSocketStream<TlsStream<TcpStream>>) -> Self {
        Self { socket }
    }

    /// Waits for the next update. `Ok(None)` means the console closed the
    /// stream; the caller should reconnect. Frames that cannot be decoded
    /// are logged and skipped, since one odd update must not stop the rest.
    pub async fn next(&mut self) -> Result<Option<Update>, crate::Error> {
        loop {
            let Some(message) = self.socket.next().await else { return Ok(None) };
            match message.map_err(|e| crate::Error::Protocol(format!("update stream: {e}")))? {
                Message::Binary(bytes) => match decode_packet(&bytes) {
                    Ok(update) => return Ok(Some(update)),
                    Err(e) => tracing::warn!("skipping undecodable Protect update: {e}"),
                },
                Message::Close(_) => return Ok(None),
                // Pings are answered by the WebSocket layer itself.
                _ => {}
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) fn frame(kind: u8, format: u8, deflate: bool, payload: &[u8]) -> Vec<u8> {
        let body = if deflate {
            let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(payload).unwrap();
            encoder.finish().unwrap()
        } else {
            payload.to_vec()
        };
        let mut out = vec![kind, format, deflate as u8, 0];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub(crate) fn packet(action: &str, data: &str, deflate: bool) -> Vec<u8> {
        let mut out = frame(FRAME_ACTION, FORMAT_JSON, deflate, action.as_bytes());
        out.extend(frame(FRAME_DATA, FORMAT_JSON, deflate, data.as_bytes()));
        out
    }

    const ACTION: &str = r#"{"action":"update","newUpdateId":"u2","modelKey":"camera","id":"c1"}"#;

    #[test]
    fn decodes_plain_and_compressed_packets() {
        for deflate in [false, true] {
            let update = decode_packet(&packet(ACTION, r#"{"isMotionDetected":true}"#, deflate)).unwrap();
            assert_eq!((update.action.as_str(), update.model_key.as_str(), update.id.as_str()), ("update", "camera", "c1"));
            assert_eq!(update.new_update_id.as_deref(), Some("u2"));
            assert_eq!(update.data["isMotionDetected"], true);
        }
    }

    #[test]
    fn non_json_data_frames_decode_to_null() {
        let mut bytes = frame(FRAME_ACTION, FORMAT_JSON, false, ACTION.as_bytes());
        bytes.extend(frame(FRAME_DATA, 3, false, &[0xde, 0xad]));
        assert_eq!(decode_packet(&bytes).unwrap().data, Value::Null);
    }

    #[test]
    fn rejects_malformed_packets() {
        let good = packet(ACTION, "{}", false);
        assert_eq!(decode_packet(&good[..5]), Err(DecodeError::Truncated));
        assert_eq!(decode_packet(&good[..good.len() - 1]), Err(DecodeError::Truncated));
        // A header that claims far more payload than is present.
        let mut lying = good.clone();
        lying[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode_packet(&lying), Err(DecodeError::Truncated));
        // Frames in the wrong order.
        let mut swapped = frame(FRAME_DATA, FORMAT_JSON, false, b"{}");
        swapped.extend(frame(FRAME_ACTION, FORMAT_JSON, false, ACTION.as_bytes()));
        assert_eq!(decode_packet(&swapped), Err(DecodeError::FrameType(FRAME_DATA)));
        // Marked compressed but is not.
        let mut bogus = frame(FRAME_ACTION, FORMAT_JSON, false, ACTION.as_bytes());
        bogus[2] = 1;
        bogus.extend(frame(FRAME_DATA, FORMAT_JSON, false, b"{}"));
        assert_eq!(decode_packet(&bogus), Err(DecodeError::Compression));
        assert!(matches!(decode_packet(&packet("not json", "{}", false)), Err(DecodeError::Json(_))));
    }

    #[test]
    fn refuses_decompression_bombs() {
        // Sixteen megabytes and one byte of zeros compress to a few kilobytes.
        let bomb = vec![0u8; MAX_PAYLOAD as usize + 1];
        let mut bytes = frame(FRAME_ACTION, FORMAT_JSON, true, &bomb);
        bytes.extend(frame(FRAME_DATA, FORMAT_JSON, false, b"{}"));
        assert!(bytes.len() < 64 * 1024);
        assert_eq!(decode_packet(&bytes), Err(DecodeError::TooLarge));
    }
}
