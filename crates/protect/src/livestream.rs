//! Protect's native live video feed.
//!
//! The console sends fragmented MP4 over a WebSocket: first an
//! initialization segment describing the tracks, then a stream of short
//! media fragments, each starting on a frame boundary. This is the feed the
//! Protect apps use themselves.
//!
//! The bytes are wrapped in small frames that may be split across WebSocket
//! messages: one type byte, a three-byte big-endian length, then the
//! payload. A media fragment arrives as several frames between a *begin*
//! and an *end* marker.

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const FRAME_TIMESTAMP: u8 = 247;
const FRAME_CODEC: u8 = 248;
const FRAME_BEGIN: u8 = 249;
const FRAME_INIT: u8 = 250;
const FRAME_MOOF: u8 = 251;
const FRAME_VIDEO: u8 = 252;
const FRAME_AUDIO: u8 = 253;
const FRAME_MDAT: u8 = 254;
const FRAME_END: u8 = 255;
const HEADER_LEN: usize = 4;

/// Largest media fragment accepted. Fragments are a fraction of a second of
/// video; this stops a corrupt stream from growing without limit.
const MAX_FRAGMENT: usize = 32 * 1024 * 1024;

/// One piece of the feed, ready to be written to a player or a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    /// The MP4 header. Sent once, before any media.
    Init {
        /// The codecs in the stream as the console names them, if it said.
        codec: Option<String>,
        data: Bytes,
    },
    /// One complete fragment of video and audio.
    Media(Bytes),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeedError {
    #[error("unknown frame type {0} in the live feed")]
    FrameType(u8),
    #[error("a live feed fragment grew past {MAX_FRAGMENT} bytes")]
    TooLarge,
}

/// How many frames of each type have been seen, for diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameCounts {
    pub codec: u64,
    pub init: u64,
    pub begin: u64,
    pub moof: u64,
    pub mdat: u64,
    pub video: u64,
    pub audio: u64,
    pub end: u64,
    pub timestamp: u64,
}

/// The parts of the fragment being assembled, kept apart because they are
/// written out in a fixed order whatever order they arrived in.
#[derive(Default)]
struct Fragment {
    moof: Vec<u8>,
    mdat: Vec<u8>,
    video: Vec<u8>,
    audio: Vec<u8>,
}

impl Fragment {
    fn len(&self) -> usize {
        self.moof.len() + self.mdat.len() + self.video.len() + self.audio.len()
    }
}

/// Turns the bytes of the feed into segments. Holds no connection, so it
/// can be tested and reused on recorded data.
#[derive(Default)]
pub struct Decoder {
    /// Bytes of a frame that has not fully arrived yet.
    pending: Vec<u8>,
    fragment: Fragment,
    codec: Option<String>,
    counts: FrameCounts,
}

impl Decoder {
    pub fn counts(&self) -> FrameCounts {
        self.counts
    }

    /// Adds the bytes of one WebSocket message and appends every segment
    /// they complete to `out`. After an error the decoder must be dropped:
    /// the position in the stream is lost.
    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<Segment>) -> Result<(), FeedError> {
        self.pending.extend_from_slice(bytes);
        let mut offset = 0;
        while let Some(header) = self.pending.get(offset..offset + HEADER_LEN) {
            let kind = header[0];
            if !(FRAME_TIMESTAMP..=FRAME_END).contains(&kind) {
                return Err(FeedError::FrameType(kind));
            }
            let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
            let start = offset + HEADER_LEN;
            if self.pending.len() < start + length {
                break;
            }
            // Split the borrow: the payload is read while the rest is updated.
            let payload = self.pending[start..start + length].to_vec();
            self.frame(kind, payload, out)?;
            offset = start + length;
        }
        self.pending.drain(..offset);
        if self.pending.len() > MAX_FRAGMENT {
            return Err(FeedError::TooLarge);
        }
        Ok(())
    }

    fn frame(&mut self, kind: u8, payload: Vec<u8>, out: &mut Vec<Segment>) -> Result<(), FeedError> {
        match kind {
            FRAME_CODEC => {
                self.counts.codec += 1;
                self.codec = Some(String::from_utf8_lossy(&payload).into_owned());
            }
            FRAME_INIT => {
                self.counts.init += 1;
                out.push(Segment::Init { codec: self.codec.clone(), data: payload.into() });
            }
            FRAME_BEGIN => {
                self.counts.begin += 1;
                self.fragment = Fragment::default();
            }
            FRAME_MOOF => {
                self.counts.moof += 1;
                self.fragment.moof.extend_from_slice(&payload);
            }
            FRAME_MDAT => {
                self.counts.mdat += 1;
                self.fragment.mdat.extend_from_slice(&payload);
            }
            FRAME_VIDEO => {
                self.counts.video += 1;
                self.fragment.video.extend_from_slice(&payload);
            }
            FRAME_AUDIO => {
                self.counts.audio += 1;
                self.fragment.audio.extend_from_slice(&payload);
            }
            FRAME_END => {
                self.counts.end += 1;
                let fragment = std::mem::take(&mut self.fragment);
                if fragment.len() > 0 {
                    let mut data = Vec::with_capacity(fragment.len());
                    for part in [fragment.moof, fragment.mdat, fragment.video, fragment.audio] {
                        data.extend_from_slice(&part);
                    }
                    out.push(Segment::Media(data.into()));
                }
            }
            // Per-frame decode times, only sent when asked for.
            _ => self.counts.timestamp += 1,
        }
        if self.fragment.len() > MAX_FRAGMENT {
            return Err(FeedError::TooLarge);
        }
        Ok(())
    }
}

/// Which of a camera's streams to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedOptions {
    /// 0 is the camera's best quality, higher numbers are smaller.
    pub channel: u8,
    /// How much video each fragment holds, in milliseconds. Shorter means
    /// less delay.
    pub fragment_ms: u32,
}

impl Default for FeedOptions {
    fn default() -> Self {
        Self { channel: 0, fragment_ms: 100 }
    }
}

/// The query string that asks the console for a feed. `camera_id` must
/// already be known to contain only letters and digits.
pub(crate) fn query(camera_id: &str, options: FeedOptions) -> String {
    // Parameters with no value are switches: fragments are sent as they
    // are produced, without waiting for a whole group of pictures.
    format!(
        "allowPartialGOP=&camera={camera_id}&channel={}&chunkSize=4096&fragmentDurationMillis={}&lens=0\
         &progressive=&rebaseTimestampsToZero=true&requestId={camera_id}-{}&type=fmp4&useWallClock=false",
        options.channel,
        options.fragment_ms.max(100),
        options.channel
    )
}

/// The path and query of the address the console handed out for a feed.
/// The console names itself by an internal address there, so only this part
/// is used and the connection goes to the pinned console as usual.
pub(crate) fn path_of(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let path = &after_scheme[after_scheme.find('/')?..];
    // Refuse anything that could not be sent as a request line unchanged.
    let safe = path.len() <= 2048 && path.bytes().all(|b| b.is_ascii_graphic() && b != b'#');
    safe.then_some(path)
}

/// A live connection to a camera's feed.
pub struct Livestream {
    socket: WebSocketStream<TlsStream<TcpStream>>,
    decoder: Decoder,
    ready: std::collections::VecDeque<Segment>,
}

impl Livestream {
    pub(crate) fn new(socket: WebSocketStream<TlsStream<TcpStream>>) -> Self {
        Self { socket, decoder: Decoder::default(), ready: Default::default() }
    }

    pub fn counts(&self) -> FrameCounts {
        self.decoder.counts()
    }

    /// Waits for the next segment. `Ok(None)` means the console closed the
    /// feed.
    pub async fn next(&mut self) -> Result<Option<Segment>, crate::Error> {
        let protocol = |e: &dyn std::fmt::Display| crate::Error::Protocol(format!("live feed: {e}"));
        loop {
            if let Some(segment) = self.ready.pop_front() {
                return Ok(Some(segment));
            }
            let Some(message) = self.socket.next().await else { return Ok(None) };
            match message.map_err(|e| protocol(&e))? {
                Message::Binary(bytes) => {
                    let mut out = Vec::new();
                    self.decoder.feed(&bytes, &mut out).map_err(|e| protocol(&e))?;
                    self.ready.extend(out);
                }
                Message::Close(_) => return Ok(None),
                // Pings are answered by the WebSocket layer itself.
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(payload);
        out
    }

    fn sample() -> Vec<u8> {
        let mut bytes = frame(FRAME_CODEC, b"avc1.640028,mp4a.40.2");
        bytes.extend(frame(FRAME_INIT, b"ftyp-moov"));
        bytes.extend(frame(FRAME_BEGIN, b""));
        // Deliberately out of order: the fragment is written moof first.
        bytes.extend(frame(FRAME_MDAT, b"[mdat]"));
        bytes.extend(frame(FRAME_MOOF, b"[moof]"));
        bytes.extend(frame(FRAME_VIDEO, b"vv"));
        bytes.extend(frame(FRAME_AUDIO, b"a"));
        bytes.extend(frame(FRAME_VIDEO, b"VV"));
        bytes.extend(frame(FRAME_END, b""));
        bytes
    }

    fn expected() -> Vec<Segment> {
        vec![
            Segment::Init { codec: Some("avc1.640028,mp4a.40.2".into()), data: Bytes::from_static(b"ftyp-moov") },
            Segment::Media(Bytes::from_static(b"[moof][mdat]vvVVa")),
        ]
    }

    #[test]
    fn assembles_init_and_media_segments() {
        let mut decoder = Decoder::default();
        let mut out = Vec::new();
        decoder.feed(&sample(), &mut out).unwrap();
        assert_eq!(out, expected());
        let counts = decoder.counts();
        assert_eq!((counts.init, counts.begin, counts.video, counts.audio, counts.end), (1, 1, 2, 1, 1));
    }

    #[test]
    fn frames_split_across_messages_at_any_point_decode_the_same() {
        let bytes = sample();
        for split in 0..=bytes.len() {
            let mut decoder = Decoder::default();
            let mut out = Vec::new();
            decoder.feed(&bytes[..split], &mut out).unwrap();
            decoder.feed(&bytes[split..], &mut out).unwrap();
            assert_eq!(out, expected(), "split at {split}");
        }
    }

    #[test]
    fn a_new_fragment_discards_an_unfinished_one() {
        let mut bytes = frame(FRAME_BEGIN, b"");
        bytes.extend(frame(FRAME_MOOF, b"stale"));
        bytes.extend(frame(FRAME_BEGIN, b""));
        bytes.extend(frame(FRAME_MOOF, b"fresh"));
        bytes.extend(frame(FRAME_END, b""));
        // An end with nothing gathered produces no segment.
        bytes.extend(frame(FRAME_END, b""));
        let mut out = Vec::new();
        Decoder::default().feed(&bytes, &mut out).unwrap();
        assert_eq!(out, [Segment::Media(Bytes::from_static(b"fresh"))]);
    }

    #[test]
    fn rejects_unknown_frames_and_runaway_fragments() {
        let mut out = Vec::new();
        assert_eq!(Decoder::default().feed(&frame(7, b"x"), &mut out), Err(FeedError::FrameType(7)));

        let mut decoder = Decoder::default();
        decoder.feed(&frame(FRAME_BEGIN, b""), &mut out).unwrap();
        let chunk = frame(FRAME_VIDEO, &vec![0u8; 8 * 1024 * 1024]);
        let mut result = Ok(());
        for _ in 0..5 {
            result = decoder.feed(&chunk, &mut out);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(FeedError::TooLarge));
        assert!(out.is_empty());
    }

    #[test]
    fn builds_the_request_and_keeps_only_the_path_of_the_answer() {
        let q = query("abc123", FeedOptions { channel: 1, fragment_ms: 20 });
        assert!(q.starts_with("allowPartialGOP=&camera=abc123&channel=1&chunkSize=4096&fragmentDurationMillis=100&"), "{q}");
        assert!(q.ends_with("&requestId=abc123-1&type=fmp4&useWallClock=false"), "{q}");
        assert!(!q.contains(' '), "{q}");

        assert_eq!(path_of("wss://192.168.1.1:7443/ws/livestream?token=ab-c_d&x=1"), Some("/ws/livestream?token=ab-c_d&x=1"));
        assert_eq!(path_of("wss://host"), None);
        assert_eq!(path_of("no scheme"), None);
        assert_eq!(path_of("wss://host/a b"), None);
        assert_eq!(path_of("wss://host/a\r\nX: y"), None);
    }
}
