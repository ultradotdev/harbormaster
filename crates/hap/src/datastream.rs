//! HomeKit data streams: the side channel a home hub opens to pull a
//! camera's recordings.
//!
//! A controller asks for a stream over its normal encrypted connection and
//! both sides derive fresh keys from that connection's shared secret. The
//! controller then connects to a separate TCP port and proves itself by
//! sending a first message that only those keys can decrypt. Messages are
//! framed as a type byte, a three-byte length, the encrypted payload and a
//! 16-byte authentication tag.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::crypto::{hkdf, open, random, seal};
use crate::opack::Value;

const FRAME_TYPE: u8 = 1;
const HEADER_LEN: usize = 4;
const TAG_LEN: usize = 16;
/// The length field has twenty usable bits.
const MAX_PAYLOAD: usize = 0xF_FFFF;
/// Recordings are sent in pieces of at most this size.
const MAX_CHUNK: usize = 0x4_0000;
/// How long a controller has to connect after asking, and to say hello
/// after connecting.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PREPARED: usize = 16;
const MAX_CONNECTIONS: usize = 32;

const STATUS_OK: i64 = 0;
const STATUS_PROTOCOL_ERROR: i64 = 6;

/// Why a recording cannot be sent, in the protocol's own numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    NotAllowed = 1,
    Busy = 2,
    Unexpected = 5,
}

/// Supplies recordings when a home hub asks for one.
pub trait RecordingSource: Send + Sync {
    /// Starts a recording for the accessory `aid`. The receiver yields the
    /// MP4 header first and then one fragment at a time; closing it ends
    /// the recording, and dropping it tells the source to stop.
    fn open(&self, aid: u64) -> Result<mpsc::Receiver<Vec<u8>>, Refusal>;
}

/// Keys agreed for a stream the controller has not connected to yet.
struct Prepared {
    aid: u64,
    /// Decrypts what the controller sends.
    read_key: [u8; 32],
    /// Encrypts what the accessory sends.
    write_key: [u8; 32],
    created: Instant,
}

pub struct DataStreams {
    port: u16,
    prepared: Mutex<Vec<Prepared>>,
    connections: Mutex<usize>,
    source: Arc<dyn RecordingSource>,
}

impl DataStreams {
    /// Starts listening on a free port. Must be called from within the
    /// async runtime.
    pub fn start(source: Arc<dyn RecordingSource>) -> std::io::Result<Arc<Self>> {
        let listener =
            std::net::TcpListener::bind("[::]:0").or_else(|_| std::net::TcpListener::bind("0.0.0.0:0"))?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        let port = listener.local_addr()?.port();
        let streams =
            Arc::new(Self { port, prepared: Mutex::new(Vec::new()), connections: Mutex::new(0), source });
        let accepting = Arc::downgrade(&streams);
        tokio::spawn(async move {
            loop {
                let Ok((socket, peer)) = listener.accept().await else {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                };
                let Some(streams) = accepting.upgrade() else { return };
                {
                    let mut count = streams.connections.lock().unwrap();
                    if *count >= MAX_CONNECTIONS {
                        tracing::warn!("refusing a data stream from {}: too many are open", peer.ip());
                        continue;
                    }
                    *count += 1;
                }
                tokio::spawn(async move {
                    if let Err(why) = streams.serve(socket, peer.ip()).await {
                        tracing::info!("data stream from {} ended: {why}", peer.ip());
                    }
                    *streams.connections.lock().unwrap() -= 1;
                });
            }
        });
        Ok(streams)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Agrees keys for a stream on behalf of accessory `aid` and returns
    /// this side's salt, or `None` if too many requests are waiting.
    pub fn prepare(&self, aid: u64, shared_secret: &[u8; 32], controller_salt: &[u8]) -> Option<[u8; 32]> {
        let accessory_salt: [u8; 32] = random();
        let salt = [controller_salt, &accessory_salt].concat();
        let mut prepared = self.prepared.lock().unwrap();
        prepared.retain(|p| p.created.elapsed() < HANDSHAKE_TIMEOUT);
        if prepared.len() >= MAX_PREPARED {
            return None;
        }
        prepared.push(Prepared {
            aid,
            read_key: hkdf(&salt, b"HDS-Write-Encryption-Key", shared_secret),
            write_key: hkdf(&salt, b"HDS-Read-Encryption-Key", shared_secret),
            created: Instant::now(),
        });
        Some(accessory_salt)
    }

    /// Finds the prepared stream whose key decrypts the first frame.
    fn identify(&self, header: &[u8], sealed: &[u8]) -> Option<(Prepared, Vec<u8>)> {
        let mut prepared = self.prepared.lock().unwrap();
        prepared.retain(|p| p.created.elapsed() < HANDSHAKE_TIMEOUT);
        let (index, plain) = prepared
            .iter()
            .enumerate()
            .find_map(|(i, p)| Some((i, open(&p.read_key, &0u64.to_le_bytes(), header, sealed)?)))?;
        Some((prepared.remove(index), plain))
    }

    async fn serve(&self, socket: TcpStream, peer: std::net::IpAddr) -> Result<(), &'static str> {
        let (mut reader, mut writer) = socket.into_split();
        let mut frames = Frames::default();

        let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, frames.next(&mut reader))
            .await
            .map_err(|_| "nothing was sent")??;
        let (session, plain) = self.identify(&first.0, &first.1).ok_or("no prepared stream matches")?;
        let hello = Message::parse(&plain).ok_or("the first message could not be read")?;
        let Kind::Request(id) = hello.kind else { return Err("the first message was not a request") };
        if (hello.protocol.as_str(), hello.topic.as_str()) != ("control", "hello") {
            return Err("the first message was not a hello");
        }

        // One task owns the sending half so frames go out whole and with
        // their counters in order.
        let (outgoing, mut queue) = mpsc::channel::<Vec<u8>>(8);
        let write_key = session.write_key;
        tokio::spawn(async move {
            let mut counter = 0u64;
            while let Some(payload) = queue.recv().await {
                let mut frame = vec![FRAME_TYPE];
                frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
                let sealed = seal(&write_key, &counter.to_le_bytes(), &frame, &payload);
                frame.extend_from_slice(&sealed);
                counter += 1;
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });
        let reply = |topic: &str, id: i64, status: i64, body: Value| {
            payload(
                Value::dict([
                    ("protocol", Value::Str("dataSend".into())),
                    ("response", Value::Str(topic.into())),
                    ("id", Value::Wide(id)),
                    ("status", Value::Wide(status)),
                ]),
                body,
            )
        };
        let hello_reply = payload(
            Value::dict([
                ("protocol", Value::Str("control".into())),
                ("response", Value::Str("hello".into())),
                ("id", Value::Wide(id)),
                ("status", Value::Wide(STATUS_OK)),
            ]),
            Value::Dict(Vec::new()),
        );
        outgoing.send(hello_reply).await.map_err(|_| "the connection closed")?;
        tracing::info!("data stream opened by {peer} for accessory {}", session.aid);

        let mut counter = 1u64;
        // The recording being sent, if any, and the id the hub gave it.
        let mut sending: Option<(i64, tokio::task::JoinHandle<()>)> = None;
        let result = loop {
            let (header, sealed) = match frames.next(&mut reader).await {
                Ok(frame) => frame,
                Err(why) => break Err(why),
            };
            let Some(plain) = open(&session.read_key, &counter.to_le_bytes(), &header, &sealed) else {
                break Err("a frame failed authentication");
            };
            counter += 1;
            let Some(message) = Message::parse(&plain) else { continue };
            let stream_id = message.body.get("streamId").and_then(Value::as_i64);
            match (message.protocol.as_str(), message.topic.as_str(), message.kind) {
                ("dataSend", "open", Kind::Request(id)) => {
                    let wanted = (
                        message.body.get("type").and_then(Value::as_str),
                        message.body.get("target").and_then(Value::as_str),
                    );
                    let opened = match (wanted, stream_id) {
                        ((Some("ipcamera.recording"), Some("controller")), Some(stream_id)) => {
                            self.source.open(session.aid).map(|fragments| (stream_id, fragments))
                        }
                        _ => {
                            tracing::info!("data stream from {peer}: refusing a request for {wanted:?}");
                            Err(Refusal::Unexpected)
                        }
                    };
                    let answer = match opened {
                        Ok((stream_id, fragments)) => {
                            if let Some((_, previous)) = sending.take() {
                                previous.abort();
                            }
                            let task = tokio::spawn(send_recording(stream_id, fragments, outgoing.clone()));
                            sending = Some((stream_id, task));
                            reply("open", id, STATUS_OK, Value::dict([("status", Value::Int(STATUS_OK))]))
                        }
                        Err(refusal) => reply(
                            "open",
                            id,
                            STATUS_PROTOCOL_ERROR,
                            Value::dict([("status", Value::Int(refusal as i64))]),
                        ),
                    };
                    if outgoing.send(answer).await.is_err() {
                        break Err("the connection closed");
                    }
                }
                // The hub has what it wants, or has given up.
                ("dataSend", "close" | "ack", Kind::Event)
                    if sending.as_ref().is_some_and(|(id, _)| Some(*id) == stream_id) =>
                {
                    let reason = message.body.get("reason").and_then(|v| v.as_i64());
                    tracing::info!("data stream from {peer}: the hub sent {} (reason {reason:?})", message.topic);
                    if let Some((_, task)) = sending.take() {
                        task.abort();
                    }
                }
                _ => {}
            }
        };
        if let Some((_, task)) = sending {
            task.abort();
        }
        result
    }
}

/// Sends a recording as it is produced: each fragment split into chunks,
/// numbered so the hub can reassemble them.
async fn send_recording(stream_id: i64, mut fragments: mpsc::Receiver<Vec<u8>>, outgoing: mpsc::Sender<Vec<u8>>) {
    let event = |topic: &str| {
        Value::dict([("protocol", Value::Str("dataSend".into())), ("event", Value::Str(topic.into()))])
    };
    let mut sequence = 1i64;
    while let Some(fragment) = fragments.recv().await {
        let kind = if sequence == 1 { "mediaInitialization" } else { "mediaFragment" };
        let chunks = fragment.chunks(MAX_CHUNK).count();
        for (index, chunk) in fragment.chunks(MAX_CHUNK).enumerate() {
            let mut metadata = vec![
                ("dataType", Value::Str(kind.into())),
                ("dataSequenceNumber", Value::Int(sequence)),
                ("dataChunkSequenceNumber", Value::Int(index as i64 + 1)),
                ("isLastDataChunk", Value::Bool(index + 1 == chunks)),
            ];
            if index == 0 {
                metadata.push(("dataTotalSize", Value::Int(fragment.len() as i64)));
            }
            let metadata = Value::Dict(metadata.into_iter().map(|(k, v)| (Value::Str(k.into()), v)).collect());
            let packet = Value::dict([("data", Value::Data(chunk.to_vec())), ("metadata", metadata)]);
            let body = Value::dict([("streamId", Value::Int(stream_id)), ("packets", Value::Array(vec![packet]))]);
            if outgoing.send(payload(event("data"), body)).await.is_err() {
                return;
            }
        }
        sequence += 1;
    }
    // The source ended the recording; say so rather than leave the hub waiting.
    let body = Value::dict([("streamId", Value::Int(stream_id)), ("reason", Value::Int(0))]);
    let _ = outgoing.send(payload(event("close"), body)).await;
}

/// A message's bytes before encryption: the header's length, the header,
/// then the body.
fn payload(header: Value, body: Value) -> Vec<u8> {
    let header = header.encode();
    let mut out = vec![header.len() as u8];
    out.extend_from_slice(&header);
    out.extend_from_slice(&body.encode());
    debug_assert!(out.len() <= MAX_PAYLOAD);
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Event,
    Request(i64),
    Response(i64),
}

struct Message {
    protocol: String,
    topic: String,
    kind: Kind,
    body: Value,
}

impl Message {
    fn parse(plain: &[u8]) -> Option<Self> {
        let (&header_len, rest) = plain.split_first()?;
        let (header, body) = rest.split_at_checked(header_len as usize)?;
        let header = Value::decode(header)?;
        let text = |key: &str| header.get(key).and_then(Value::as_str).map(str::to_owned);
        let id = header.get("id").and_then(Value::as_i64);
        let (topic, kind) = if let Some(topic) = text("event") {
            (topic, Kind::Event)
        } else if let Some(topic) = text("request") {
            (topic, Kind::Request(id?))
        } else {
            (text("response")?, Kind::Response(id?))
        };
        Some(Self { protocol: text("protocol")?, topic, kind, body: Value::decode(body)? })
    }
}

/// Splits what arrives on the socket into frames.
#[derive(Default)]
struct Frames {
    buffer: Vec<u8>,
}

impl Frames {
    /// The next frame's header and its encrypted payload with tag.
    async fn next<R: AsyncReadExt + Unpin>(&mut self, reader: &mut R) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        loop {
            if let Some(header) = self.buffer.get(..HEADER_LEN) {
                if header[0] != FRAME_TYPE {
                    return Err("unknown frame type");
                }
                let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
                if length > MAX_PAYLOAD {
                    return Err("frame too large");
                }
                let end = HEADER_LEN + length + TAG_LEN;
                if self.buffer.len() >= end {
                    let frame: Vec<u8> = self.buffer.drain(..end).collect();
                    return Ok((frame[..HEADER_LEN].to_vec(), frame[HEADER_LEN..].to_vec()));
                }
            }
            let mut chunk = [0u8; 16 * 1024];
            match reader.read(&mut chunk).await {
                Ok(0) | Err(_) => return Err("the connection closed"),
                Ok(n) => self.buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hands out one recording: a header and two fragments, the second
    /// larger than a single chunk.
    struct Canned {
        allow: bool,
    }

    impl RecordingSource for Canned {
        fn open(&self, aid: u64) -> Result<mpsc::Receiver<Vec<u8>>, Refusal> {
            assert_eq!(aid, 5);
            if !self.allow {
                return Err(Refusal::NotAllowed);
            }
            let (sender, receiver) = mpsc::channel(4);
            tokio::spawn(async move {
                for fragment in [vec![1u8; 100], vec![2u8; 300], vec![3u8; MAX_CHUNK + 10]] {
                    if sender.send(fragment).await.is_err() {
                        return;
                    }
                }
            });
            Ok(receiver)
        }
    }

    /// The controller's side of a stream.
    struct Client {
        socket: TcpStream,
        frames: Frames,
        write_key: [u8; 32],
        read_key: [u8; 32],
        sent: u64,
        received: u64,
    }

    impl Client {
        async fn connect(streams: &DataStreams, secret: &[u8; 32]) -> Self {
            let controller_salt = [9u8; 32];
            let accessory_salt = streams.prepare(5, secret, &controller_salt).unwrap();
            let salt = [&controller_salt[..], &accessory_salt[..]].concat();
            Self {
                socket: TcpStream::connect(("127.0.0.1", streams.port())).await.unwrap(),
                frames: Frames::default(),
                write_key: hkdf(&salt, b"HDS-Write-Encryption-Key", secret),
                read_key: hkdf(&salt, b"HDS-Read-Encryption-Key", secret),
                sent: 0,
                received: 0,
            }
        }

        async fn send(&mut self, header: Value, body: Value) {
            let plain = payload(header, body);
            let mut frame = vec![FRAME_TYPE];
            frame.extend_from_slice(&(plain.len() as u32).to_be_bytes()[1..]);
            let sealed = seal(&self.write_key, &self.sent.to_le_bytes(), &frame, &plain);
            frame.extend_from_slice(&sealed);
            self.sent += 1;
            self.socket.write_all(&frame).await.unwrap();
        }

        async fn request(&mut self, protocol: &str, topic: &str, id: i64, body: Value) {
            let header = Value::dict([
                ("protocol", Value::Str(protocol.into())),
                ("request", Value::Str(topic.into())),
                ("id", Value::Wide(id)),
            ]);
            self.send(header, body).await;
        }

        async fn receive(&mut self) -> Option<Message> {
            let next = tokio::time::timeout(Duration::from_secs(5), self.frames.next(&mut self.socket));
            let (header, sealed) = next.await.expect("timed out waiting for the accessory").ok()?;
            let plain = open(&self.read_key, &self.received.to_le_bytes(), &header, &sealed).expect("bad frame");
            self.received += 1;
            Some(Message::parse(&plain).expect("unreadable message"))
        }

        async fn hello(&mut self) {
            self.request("control", "hello", 1, Value::Dict(Vec::new())).await;
            let reply = self.receive().await.unwrap();
            assert_eq!((reply.protocol.as_str(), reply.topic.as_str(), reply.kind), ("control", "hello", Kind::Response(1)));
        }

        async fn open_recording(&mut self) -> Message {
            let body = Value::dict([
                ("streamId", Value::Int(3)),
                ("type", Value::Str("ipcamera.recording".into())),
                ("target", Value::Str("controller".into())),
            ]);
            self.request("dataSend", "open", 2, body).await;
            let reply = self.receive().await.unwrap();
            assert_eq!((reply.topic.as_str(), reply.kind), ("open", Kind::Response(2)));
            reply
        }
    }

    #[tokio::test]
    async fn sends_a_recording_in_numbered_chunks() {
        let streams = DataStreams::start(Arc::new(Canned { allow: true })).unwrap();
        let mut client = Client::connect(&streams, &[4; 32]).await;
        client.hello().await;
        assert_eq!(client.open_recording().await.body.get("status").and_then(Value::as_i64), Some(0));

        // (type, fragment number, chunk number, last chunk, total size, bytes)
        let mut seen = Vec::new();
        loop {
            let message = client.receive().await.unwrap();
            assert_eq!(message.body.get("streamId").and_then(Value::as_i64), Some(3));
            if message.topic == "close" {
                assert_eq!(message.body.get("reason").and_then(Value::as_i64), Some(0));
                break;
            }
            let Some(Value::Array(packets)) = message.body.get("packets") else { panic!("no packets") };
            let metadata = packets[0].get("metadata").unwrap();
            let number = |key| metadata.get(key).and_then(Value::as_i64);
            let Some(Value::Data(data)) = packets[0].get("data") else { panic!("no data") };
            seen.push((
                metadata.get("dataType").and_then(Value::as_str).unwrap().to_owned(),
                number("dataSequenceNumber").unwrap(),
                number("dataChunkSequenceNumber").unwrap(),
                metadata.get("isLastDataChunk") == Some(&Value::Bool(true)),
                number("dataTotalSize"),
                data.len(),
            ));
        }
        let total = Some((MAX_CHUNK + 10) as i64);
        assert_eq!(
            seen,
            [
                ("mediaInitialization".to_owned(), 1, 1, true, Some(100), 100),
                ("mediaFragment".to_owned(), 2, 1, true, Some(300), 300),
                ("mediaFragment".to_owned(), 3, 1, false, total, MAX_CHUNK),
                ("mediaFragment".to_owned(), 3, 2, true, None, 10),
            ]
        );
    }

    #[tokio::test]
    async fn refusals_reach_the_hub_and_strangers_are_dropped() {
        let streams = DataStreams::start(Arc::new(Canned { allow: false })).unwrap();
        let mut client = Client::connect(&streams, &[4; 32]).await;
        client.hello().await;
        let reply = client.open_recording().await;
        assert_eq!(reply.body.get("status").and_then(Value::as_i64), Some(Refusal::NotAllowed as i64));

        // Right port, wrong keys: the connection is closed without a reply.
        let mut stranger = Client::connect(&streams, &[4; 32]).await;
        stranger.write_key = [0; 32];
        stranger.request("control", "hello", 1, Value::Dict(Vec::new())).await;
        assert!(stranger.receive().await.is_none());

        // A prepared stream can be claimed only once.
        assert!(streams.prepared.lock().unwrap().iter().all(|p| p.aid == 5));
        assert_eq!(streams.prepared.lock().unwrap().len(), 1, "only the stranger's unused keys remain");
    }

    #[tokio::test]
    async fn waiting_requests_are_limited() {
        let streams = DataStreams::start(Arc::new(Canned { allow: true })).unwrap();
        for _ in 0..MAX_PREPARED {
            assert!(streams.prepare(5, &[1; 32], &[2; 32]).is_some());
        }
        assert!(streams.prepare(5, &[1; 32], &[2; 32]).is_none());
    }
}
