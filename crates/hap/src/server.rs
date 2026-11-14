//! The HomeKit accessory server: a small HTTP/1.1 server whose connections
//! switch to an encrypted transport once a controller has verified itself.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch, Notify, Semaphore};

use crate::mdns::Advertiser;
use crate::model::{status, Change, Database, WriteContext};
use crate::pairing::{self, SetupState, VerifyState};
use crate::session::Session;
use crate::store::Store;

/// Largest request (headers plus body) a controller may send.
const MAX_REQUEST: usize = 64 * 1024;
/// Simultaneous controller connections. Each Apple device in the home holds
/// one open, so this needs headroom well beyond the protocol minimum of 8.
const MAX_CONNECTIONS: usize = 64;
/// How long a connection that has not verified itself may stay silent, or
/// leave an answer unread, before it is closed. Without this anyone on the
/// network could open every slot, say nothing, and keep the home's own
/// devices out. Pairing takes several requests seconds apart, so this is
/// a limit on silence, not on the connection's age. Verified controllers
/// are never timed out: they hold a connection open, idle, for hours.
const UNVERIFIED_IDLE: Duration = Duration::from_secs(60);
/// How long a new connection waits for a slot to be given up when all are
/// taken.
const EVICTION_WAIT: Duration = Duration::from_secs(1);

/// HAP status: the accessory could not reach the device behind it.
const SERVICE_COMMUNICATION_FAILURE: i32 = -70402;

const TLV: &str = "application/pairing+tlv8";
const JSON: &str = "application/hap+json";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("network: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bonjour advertisement: {0}")]
    Mdns(#[from] crate::mdns::Error),
}

pub struct Config {
    /// Name shown while pairing, and the Bonjour instance name.
    pub name: String,
    pub model: String,
    /// Address to listen on. Port 0 picks a free port. An unspecified
    /// address (`0.0.0.0` or `[::]`) listens on both IPv4 and IPv6, which
    /// matters because Apple devices prefer the advertised IPv6 addresses.
    pub listen: SocketAddr,
    /// Whether to advertise over Bonjour. Tests turn this off.
    pub advertise: bool,
    /// Where camera snapshots come from, if any accessory is a camera.
    pub snapshots: Option<Arc<dyn SnapshotSource>>,
}

/// Why a controller wants a still image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotReason {
    /// A routine refresh of the picture shown in the Home app.
    Periodic,
    /// Something happened, such as motion or a doorbell press.
    Event,
    /// The controller did not say.
    Unspecified,
}

/// Supplies still images for camera accessories.
pub trait SnapshotSource: Send + Sync {
    /// A JPEG of roughly the requested size for the accessory, or `None`
    /// if it has no image to give right now.
    fn snapshot(
        &self,
        aid: u64,
        width: u32,
        height: u32,
        reason: SnapshotReason,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + '_>>;
}

/// A controller connection, for status displays.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub peer: SocketAddr,
    /// Pairing identifier, once the controller has verified itself.
    pub controller: Option<String>,
    pub connected_at: std::time::SystemTime,
}

/// One open connection: what a status display may see of it, and the
/// means to ask it to close.
struct Slot {
    info: ConnectionInfo,
    give_up: Arc<Notify>,
}

struct Shared {
    snapshots: Option<Arc<dyn SnapshotSource>>,
    /// Keyed by connection id, which rises with each connection, so the
    /// first entry is the oldest.
    connections: Mutex<BTreeMap<u64, Slot>>,
    unverified_idle: Duration,
    store: Arc<Store>,
    db: Arc<Database>,
    failed_setup_attempts: AtomicU32,
    advertiser: Mutex<Option<Advertiser>>,
    /// Bumped whenever the set of pairings changes.
    pairings_changed: watch::Sender<u64>,
}

impl Shared {
    fn publish(&self) {
        if let Some(advertiser) = self.advertiser.lock().unwrap().as_mut() {
            if let Err(e) = advertiser.publish(self.store.config_number(), self.store.is_paired()) {
                tracing::error!("could not update Bonjour advertisement: {e}");
            }
        }
    }

    fn pairings_changed(&self) {
        self.publish();
        self.pairings_changed.send_modify(|n| *n += 1);
    }
}

/// A running bridge. Dropping it stops accepting connections.
pub struct Bridge {
    pub local_addr: SocketAddr,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Bridge {
    /// Tells controllers the set of accessories or services has changed.
    pub fn config_changed(&self) {
        match self.shared.store.sync_layout(&self.shared.db.layout()) {
            Ok(true) => {
                tracing::info!("accessory database changed (configuration {})", self.shared.store.config_number())
            }
            Ok(false) => {}
            Err(e) => tracing::error!("could not save configuration number: {e}"),
        }
        self.shared.publish();
    }

    /// Tells controllers to read every accessory again, whether or not the
    /// set of accessories and services changed. For changes the database's
    /// shape does not show, such as new names.
    pub fn republish(&self) {
        let store = &self.shared.store;
        let bumped = match store.sync_layout(&self.shared.db.layout()) {
            Ok(true) => Ok(store.config_number()),
            Ok(false) => store.bump_config_number(),
            Err(e) => Err(e),
        };
        match bumped {
            Ok(number) => tracing::info!("accessories changed (configuration {number})"),
            Err(e) => tracing::error!("could not save configuration number: {e}"),
        }
        self.shared.publish();
    }

    /// Currently open controller connections, oldest first.
    pub fn connections(&self) -> Vec<ConnectionInfo> {
        self.shared.connections.lock().unwrap().values().map(|slot| slot.info.clone()).collect()
    }

    pub async fn start(config: Config, store: Arc<Store>, db: Arc<Database>) -> Result<Self, Error> {
        Self::start_with(config, store, db, MAX_CONNECTIONS, UNVERIFIED_IDLE).await
    }

    /// `start`, with the limits on connections given, so tests can reach
    /// them without sixty-four sockets and a minute's wait.
    async fn start_with(
        config: Config,
        store: Arc<Store>,
        db: Arc<Database>,
        max_connections: usize,
        unverified_idle: Duration,
    ) -> Result<Self, Error> {
        // Accessories may have been added or removed since the last run.
        match store.sync_layout(&db.layout()) {
            Ok(true) => tracing::info!("accessory database differs from the last run (configuration {})", store.config_number()),
            Ok(false) => {}
            Err(e) => tracing::error!("could not save configuration number: {e}"),
        }
        let listener = bind(config.listen).await?;
        let local_addr = listener.local_addr()?;
        let advertiser = if config.advertise {
            let mut advertiser = Advertiser::new(
                &config.name,
                &config.model,
                &store.device_id(),
                &store.setup_hash(),
                local_addr.port(),
            )?;
            // A bridge nobody can discover is useless, so fail loudly here.
            advertiser.publish(store.config_number(), store.is_paired())?;
            Some(advertiser)
        } else {
            None
        };
        let shared = Arc::new(Shared {
            snapshots: config.snapshots,
            connections: Mutex::new(BTreeMap::new()),
            unverified_idle,
            store,
            db,
            failed_setup_attempts: AtomicU32::new(0),
            advertiser: Mutex::new(advertiser),
            pairings_changed: watch::channel(0).0,
        });

        let accept_shared = shared.clone();
        let task = tokio::spawn(async move {
            let shared = accept_shared;
            let limit = Arc::new(Semaphore::new(max_connections));
            let mut next_id = 0u64;
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        // Usually file-descriptor exhaustion; back off rather than spin.
                        tracing::warn!("accept failed: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let permit = match limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // Every slot is taken. A newcomer may be one of the
                        // home's own devices, so the connection that has
                        // gone longest without verifying itself makes way.
                        // Verified controllers are never asked to.
                        let oldest_unverified = shared
                            .connections
                            .lock()
                            .unwrap()
                            .values()
                            .find(|slot| slot.info.controller.is_none())
                            .map(|slot| slot.give_up.clone());
                        let freed = match oldest_unverified {
                            Some(give_up) => {
                                give_up.notify_one();
                                tokio::time::timeout(EVICTION_WAIT, limit.clone().acquire_owned()).await.ok().and_then(Result::ok)
                            }
                            None => None,
                        };
                        let Some(permit) = freed else {
                            tracing::warn!("connection limit reached, refusing {peer}");
                            continue;
                        };
                        permit
                    }
                };
                next_id += 1;
                let (shared, id) = (shared.clone(), next_id);
                tokio::spawn(async move {
                    let _permit = permit;
                    tracing::debug!("connection {id} from {peer}");
                    let _ = stream.set_nodelay(true);
                    let info = ConnectionInfo {
                        peer,
                        controller: None,
                        connected_at: std::time::SystemTime::now(),
                    };
                    let give_up = Arc::new(Notify::new());
                    shared.connections.lock().unwrap().insert(id, Slot { info, give_up: give_up.clone() });
                    let result = Connection::new(shared.clone(), stream, id, peer).run(give_up).await;
                    shared.connections.lock().unwrap().remove(&id);
                    shared.db.connection_closed(id);
                    if let Err(e) = result {
                        tracing::debug!("connection {id} from {peer} closed: {e}");
                    }
                });
            }
        });
        Ok(Self { local_addr, shared, task })
    }
}

/// Binds the listener. For an unspecified address this prefers a dual-stack
/// IPv6 socket, which also accepts IPv4, and falls back to IPv4 alone on
/// hosts with IPv6 disabled.
async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    if !addr.ip().is_unspecified() {
        return TcpListener::bind(addr).await;
    }
    let dual = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, addr.port()));
    match TcpListener::bind(dual).await {
        Ok(listener) => Ok(listener),
        // A busy port is busy for IPv4 too; falling back would only obscure it.
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Err(std::io::Error::new(
            e.kind(),
            format!("port {} is already in use; is another Harbormaster running?", addr.port()),
        )),
        Err(e) => {
            tracing::warn!("IPv6 listener unavailable ({e}); serving IPv4 only");
            TcpListener::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, addr.port()))).await
        }
    }
}

struct Request {
    method: String,
    path: String,
    query: String,
    body: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
enum ConnectionError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("malformed request")]
    BadRequest,
    #[error("{0}")]
    BadFrame(#[from] crate::session::BadFrame),
    #[error("pairing was removed")]
    Unpaired,
    #[error("fell too far behind on events")]
    Lagged,
    #[error("sent nothing for too long without verifying itself")]
    Idle,
    #[error("made way for a newer connection while unverified")]
    MadeWay,
}

/// Takes one complete request off the front of `buf`, if there is one.
fn parse_request(buf: &mut Vec<u8>) -> Result<Option<Request>, ConnectionError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Request::new(&mut headers);
    let header_len = match parsed.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) if buf.len() <= MAX_REQUEST => return Ok(None),
        _ => return Err(ConnectionError::BadRequest),
    };
    let body_len = parsed
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|h| std::str::from_utf8(h.value).ok().and_then(|v| v.trim().parse::<usize>().ok()))
        .unwrap_or(Some(0))
        // Checked, because the length is whatever the sender wrote: one near
        // the top of the range would wrap around and pass as small.
        .filter(|n| header_len.checked_add(*n).is_some_and(|total| total <= MAX_REQUEST))
        .ok_or(ConnectionError::BadRequest)?;
    if buf.len() < header_len + body_len {
        return Ok(None);
    }
    let target = parsed.path.unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let request = Request {
        method: parsed.method.unwrap_or("").to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        body: buf[header_len..header_len + body_len].to_vec(),
    };
    buf.drain(..header_len + body_len);
    Ok(Some(request))
}

fn response(code: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        207 => "Multi-Status",
        400 => "Bad Request",
        404 => "Not Found",
        470 => "Connection Authorization Required",
        _ => "Internal Server Error",
    };
    let mut out = if code == 204 {
        format!("HTTP/1.1 204 {reason}\r\n\r\n").into_bytes()
    } else {
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes()
    };
    out.extend_from_slice(body);
    out
}

fn json_response(code: u16, body: &Value) -> Vec<u8> {
    response(code, JSON, body.to_string().as_bytes())
}

fn event(changes: &[&Change]) -> Vec<u8> {
    let items: Vec<Value> =
        changes.iter().map(|c| json!({ "aid": c.aid, "iid": c.iid, "value": c.value })).collect();
    let body = json!({ "characteristics": items }).to_string();
    format!(
        "EVENT/1.0 200 OK\r\nContent-Type: {JSON}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

struct Connection {
    shared: Arc<Shared>,
    stream: TcpStream,
    id: u64,
    peer: SocketAddr,
    /// This machine's address on the interface the controller connected to.
    local_ip: std::net::IpAddr,
    session: Option<Session>,
    /// The verified session's secret, kept for deriving side-channel keys.
    shared_secret: Option<[u8; 32]>,
    /// Identifier of the verified controller, once pair-verify has succeeded.
    controller: Option<String>,
    setup: SetupState,
    verify: Option<VerifyState>,
    subscriptions: HashSet<(u64, u64)>,
}

impl Connection {
    fn new(shared: Arc<Shared>, stream: TcpStream, id: u64, peer: SocketAddr) -> Self {
        let local_ip = stream.local_addr().map_or(peer.ip(), |a| a.ip()).to_canonical();
        Self {
            shared,
            stream,
            id,
            peer,
            local_ip,
            session: None,
            shared_secret: None,
            controller: None,
            setup: SetupState::default(),
            verify: None,
            subscriptions: HashSet::new(),
        }
    }

    async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        // A stranger who will not read its answers is not waited on for
        // longer than one who says nothing.
        let patience = self.controller.is_none().then_some(self.shared.unverified_idle);
        let write = async {
            match &mut self.session {
                Some(session) => self.stream.write_all(&session.encrypt(bytes)).await,
                None => self.stream.write_all(bytes).await,
            }
        };
        match patience {
            Some(patience) => tokio::time::timeout(patience, write)
                .await
                .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into())),
            None => write.await,
        }
    }

    async fn run(mut self, give_up: Arc<Notify>) -> Result<(), ConnectionError> {
        let mut changes = self.shared.db.subscribe_changes();
        let mut pairings = self.shared.pairings_changed.subscribe();
        let (mut raw, mut plain) = (Vec::new(), Vec::new());
        let mut chunk = [0u8; 4096];
        let mut last_heard = tokio::time::Instant::now();
        loop {
            tokio::select! {
                // Both of these are for strangers only; see `UNVERIFIED_IDLE`.
                _ = tokio::time::sleep_until(last_heard + self.shared.unverified_idle), if self.controller.is_none() => {
                    return Err(ConnectionError::Idle);
                }
                _ = give_up.notified(), if self.controller.is_none() => return Err(ConnectionError::MadeWay),
                read = self.stream.read(&mut chunk) => {
                    let n = read?;
                    if n == 0 {
                        return Ok(());
                    }
                    last_heard = tokio::time::Instant::now();
                    match &mut self.session {
                        Some(session) => {
                            raw.extend_from_slice(&chunk[..n]);
                            session.decrypt(&mut raw, &mut plain)?;
                        }
                        None => plain.extend_from_slice(&chunk[..n]),
                    }
                    while let Some(request) = parse_request(&mut plain)? {
                        let was_encrypted = self.session.is_some();
                        let (reply, upgrade) = self.handle(request).await;
                        self.send(&reply).await?;
                        if let Some(session) = upgrade {
                            self.session = Some(session);
                        }
                        // Anything already buffered after the handshake reply
                        // was sent under the new session keys.
                        if let (false, Some(session)) = (was_encrypted, &mut self.session) {
                            raw.append(&mut plain);
                            session.decrypt(&mut raw, &mut plain)?;
                        }
                    }
                }
                change = changes.recv() => match change {
                    Ok(change) => {
                        let wanted = self.subscriptions.contains(&(change.aid, change.iid));
                        if wanted && change.origin != Some(self.id) {
                            // Motion is what makes a hub ask for a recording, so
                            // who was told about it is worth a line of its own.
                            let motion = self.shared.db.with(change.aid, change.iid, |c| c.kind) == Some("22");
                            if motion && change.value == json!(true) {
                                tracing::info!("told {} about motion on accessory {}", self.peer.ip().to_canonical(), change.aid);
                            }
                            tracing::debug!(
                                "telling {} that accessory {} characteristic {} changed",
                                self.peer.ip(),
                                change.aid,
                                change.iid
                            );
                            self.send(&event(&[&change])).await?;
                        }
                    }
                    // A controller this far behind has stale state; make it reconnect.
                    Err(broadcast::error::RecvError::Lagged(_)) => return Err(ConnectionError::Lagged),
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                },
                changed = pairings.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    if let Some(id) = &self.controller {
                        if self.shared.store.pairing(id).is_none() {
                            return Err(ConnectionError::Unpaired);
                        }
                    }
                }
            }
        }
    }

    /// Produces the reply to one request and, when pair-verify completes, the
    /// session to switch to after that reply has been sent in the clear.
    async fn handle(&mut self, request: Request) -> (Vec<u8>, Option<Session>) {
        let store = self.shared.store.clone();
        let unauthorized = || json_response(470, &json!({ "status": status::INSUFFICIENT_PRIVILEGES }));
        let reply = match (request.method.as_str(), request.path.as_str(), self.controller.clone()) {
            ("POST", "/pair-setup", _) => {
                let was_paired = store.is_paired();
                let body = pairing::pair_setup(
                    &mut self.setup,
                    &store,
                    &self.shared.failed_setup_attempts,
                    &request.body,
                );
                self.log_pairing_step("pair-setup", &request.body, &body);
                if store.is_paired() != was_paired {
                    tracing::info!("paired with a controller at {}", self.peer.ip().to_canonical());
                    self.shared.pairings_changed();
                }
                response(200, TLV, &body)
            }
            ("POST", "/pair-verify", _) => {
                let (body, verified) = pairing::pair_verify(&mut self.verify, &store, &request.body);
                // Verification happens on every connection; the pairing module
                // reports the refusals that matter, so only trace progress here.
                tracing::debug!("connection {} pair-verify exchange", self.id);
                let session = verified.map(|v| {
                    tracing::debug!("connection {} verified as {}", self.id, v.controller_id);
                    if let Some(slot) = self.shared.connections.lock().unwrap().get_mut(&self.id) {
                        slot.info.controller = Some(v.controller_id.clone());
                    }
                    self.controller = Some(v.controller_id);
                    self.shared_secret = Some(v.shared_secret);
                    Session::new(&v.shared_secret)
                });
                return (response(200, TLV, &body), session);
            }
            ("POST", "/identify", _) => {
                // Unauthenticated identify is only allowed before pairing.
                if store.is_paired() {
                    json_response(400, &json!({ "status": status::INSUFFICIENT_PRIVILEGES }))
                } else {
                    response(204, "", &[])
                }
            }
            (_, _, None) => unauthorized(),
            ("POST", "/pairings", Some(controller)) => {
                let before = store.pairings().len();
                let body = pairing::pairings(&store, &controller, &request.body);
                let after = store.pairings().len();
                // Pairing changes are rare and matter, so say what happened.
                match after {
                    0 if before > 0 => tracing::info!(
                        "unpaired: a controller at {} removed the bridge from its home",
                        self.peer.ip().to_canonical()
                    ),
                    n if n != before => tracing::info!("controllers changed: {before} before, {n} now"),
                    _ => {}
                }
                self.shared.pairings_changed();
                response(200, TLV, &body)
            }
            ("GET", "/accessories", Some(_)) => {
                let list = self.shared.db.to_json();
                tracing::info!(
                    "{} read the accessory list ({} accessories)",
                    self.peer.ip().to_canonical(),
                    list["accessories"].as_array().map_or(0, Vec::len)
                );
                json_response(200, &list)
            }
            ("GET", "/characteristics", Some(_)) => self.read_characteristics(&request.query),
            ("PUT", "/characteristics", Some(_)) => self.write_characteristics(&request.body),
            // Timed writes are acknowledged; no characteristic requires them yet.
            ("POST", "/resource", Some(_)) => self.resource(&request.body).await,
            ("PUT", "/prepare", Some(_)) => json_response(200, &json!({ "status": status::OK })),
            _ => response(404, JSON, b"{}"),
        };
        (reply, None)
    }

    /// Pairing is rare and hard to debug from the phone side, so each step
    /// is logged: progress at info level, refusals as warnings.
    fn log_pairing_step(&self, what: &str, request: &[u8], reply: &[u8]) {
        use crate::tlv::{Tlv, ERROR, STATE};
        let step = Tlv::decode(request).ok().and_then(|t| t.get_u8(STATE)).unwrap_or(0);
        match Tlv::decode(reply).ok().and_then(|t| t.get_u8(ERROR)) {
            Some(code) => {
                let reason = match code {
                    crate::tlv::error::AUTHENTICATION => "wrong setup code or unknown controller",
                    crate::tlv::error::MAX_TRIES => "too many failed attempts; restart to retry",
                    crate::tlv::error::UNAVAILABLE => "already paired",
                    _ => "malformed or out-of-order request",
                };
                tracing::warn!("{what} step {step} from {} refused: {reason}", self.peer.ip().to_canonical());
            }
            None => tracing::info!("{what} step {step} from {} ok", self.peer.ip().to_canonical()),
        }
    }

    /// Serves a camera snapshot.
    async fn resource(&self, body: &[u8]) -> Vec<u8> {
        let failed = |code: i32| json_response(207, &json!({ "status": code }));
        let Ok(request) = serde_json::from_slice::<Value>(body) else {
            return json_response(400, &json!({ "status": status::INVALID_VALUE }));
        };
        if request["resource-type"] != "image" {
            return json_response(400, &json!({ "status": status::INVALID_VALUE }));
        }
        let dimension = |key: &str| request[key].as_u64().filter(|n| (1..=8192).contains(n)).map(|n| n as u32);
        let (Some(width), Some(height)) = (dimension("image-width"), dimension("image-height")) else {
            return json_response(400, &json!({ "status": status::INVALID_VALUE }));
        };
        // A bridge with one camera may omit the accessory id.
        let aid = request["aid"].as_u64().unwrap_or(1);
        let Some(source) = &self.shared.snapshots else { return failed(status::NOT_FOUND) };
        let reason = match request["reason"].as_u64() {
            Some(0) => SnapshotReason::Periodic,
            Some(1) => SnapshotReason::Event,
            _ => SnapshotReason::Unspecified,
        };
        match source.snapshot(aid, width, height, reason).await {
            Some(jpeg) => response(200, "image/jpeg", &jpeg),
            None => failed(SERVICE_COMMUNICATION_FAILURE),
        }
    }

    fn read_characteristics(&self, query: &str) -> Vec<u8> {
        let param = |name: &str| {
            query.split('&').filter_map(|p| p.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v)
        };
        let flag = |name: &str| matches!(param(name), Some("1" | "true"));
        let Some(ids) = param("id") else {
            return json_response(400, &json!({ "status": status::INVALID_VALUE }));
        };
        let (with_ev, with_type, with_perms) = (flag("ev"), flag("type"), flag("perms"));
        let mut failed = false;
        let mut items = Vec::new();
        for id in ids.split(',') {
            let Some((aid, iid)) = id
                .split_once('.')
                .and_then(|(a, i)| Some((a.parse::<u64>().ok()?, i.parse::<u64>().ok()?)))
            else {
                return json_response(400, &json!({ "status": status::INVALID_VALUE }));
            };
            let mut item = json!({ "aid": aid, "iid": iid });
            match self.shared.db.read(aid, iid) {
                Ok(value) => {
                    item["value"] = value;
                    if with_ev {
                        item["ev"] = json!(self.subscriptions.contains(&(aid, iid)));
                    }
                    if with_type || with_perms {
                        if let Some(Value::Object(full)) = self.shared.db.with(aid, iid, |c| c.describe()) {
                            if with_type {
                                item["type"] = full["type"].clone();
                            }
                            if with_perms {
                                item["perms"] = full["perms"].clone();
                            }
                        }
                    }
                }
                Err(code) => {
                    failed = true;
                    item["status"] = json!(code);
                }
            }
            items.push(item);
        }
        if failed {
            // A multi-status reply must carry a status on every item.
            for item in &mut items {
                if item.get("status").is_none() {
                    item["status"] = json!(status::OK);
                }
            }
        }
        json_response(if failed { 207 } else { 200 }, &json!({ "characteristics": items }))
    }

    fn write_characteristics(&mut self, body: &[u8]) -> Vec<u8> {
        let bad = || json_response(400, &json!({ "status": status::INVALID_VALUE }));
        let Ok(parsed) = serde_json::from_slice::<Value>(body) else { return bad() };
        let Some(writes) = parsed["characteristics"].as_array() else { return bad() };
        let mut failed = false;
        let mut with_values = false;
        let mut results = Vec::new();
        for write in writes {
            let (Some(aid), Some(iid)) = (write["aid"].as_u64(), write["iid"].as_u64()) else {
                return bad();
            };
            let mut code = status::OK;
            let mut answer = None;
            if let Some(value) = write.get("value") {
                let context = WriteContext {
                    connection: self.id,
                    local_ip: self.local_ip,
                    peer_ip: self.peer.ip().to_canonical(),
                    shared_secret: self.shared_secret,
                };
                match self.shared.db.write(aid, iid, value, &context) {
                    // The controller asked for the answer in this reply.
                    Ok(stored) if write["r"] == true => answer = Some(stored),
                    Ok(_) => {}
                    Err(e) => {
                        // Values can be sensitive, so only say what was refused.
                        let kind = self.shared.db.with(aid, iid, |c| c.kind).unwrap_or("unknown");
                        tracing::warn!(
                            "refused a write from {} to accessory {aid}, characteristic {iid} (type {kind}): status {e}",
                            self.peer.ip().to_canonical()
                        );
                        code = e;
                    }
                }
            }
            if let (status::OK, Some(subscribe)) = (code, write.get("ev")) {
                match (self.shared.db.with(aid, iid, |c| c.notifies), subscribe.as_bool()) {
                    (None, _) => code = status::NOT_FOUND,
                    (Some(false), _) => code = status::NO_NOTIFICATIONS,
                    (Some(true), Some(true)) => {
                        if self.subscriptions.insert((aid, iid)) {
                            let kind = self.shared.db.with(aid, iid, |c| c.kind).unwrap_or("unknown");
                            tracing::debug!("{} now follows accessory {aid} characteristic {iid} (type {kind})", self.peer.ip());
                        }
                    }
                    (Some(true), Some(false)) => {
                        self.subscriptions.remove(&(aid, iid));
                    }
                    (Some(true), None) => code = status::INVALID_VALUE,
                }
            }
            failed |= code != status::OK;
            let mut result = json!({ "aid": aid, "iid": iid, "status": code });
            if let (status::OK, Some(value)) = (code, answer) {
                result["value"] = value;
                with_values = true;
            }
            results.push(result);
        }
        // A reply that carries values or failures lists every write.
        if failed || with_values {
            json_response(207, &json!({ "characteristics": results }))
        } else {
            response(204, "", &[])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pipelined_requests_and_waits_for_bodies() {
        let mut buf = b"POST /pair-setup HTTP/1.1\r\nContent-Length: 3\r\n\r\nab".to_vec();
        assert!(parse_request(&mut buf).unwrap().is_none());
        buf.extend_from_slice(b"cGET /characteristics?id=1.2 HTTP/1.1\r\n\r\n");
        let first = parse_request(&mut buf).unwrap().unwrap();
        assert_eq!((first.method.as_str(), first.path.as_str(), first.body.as_slice()), ("POST", "/pair-setup", &b"abc"[..]));
        let second = parse_request(&mut buf).unwrap().unwrap();
        assert_eq!((second.path.as_str(), second.query.as_str()), ("/characteristics", "id=1.2"));
        assert!(buf.is_empty());
    }

    #[test]
    fn rejects_oversized_and_garbage_requests() {
        let mut big = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_REQUEST).into_bytes();
        assert!(parse_request(&mut big).is_err());
        let mut garbage = b"\x00\x01\x02 not http\r\n\r\n".to_vec();
        assert!(parse_request(&mut garbage).is_err());
    }

    /// Anyone on the network can send this before pairing. A length that
    /// wraps around when the header's size is added must be refused like
    /// any other oversized one, not slip past the limit.
    #[test]
    fn rejects_a_body_length_that_overflows() {
        for length in [usize::MAX.to_string(), (usize::MAX - 10).to_string(), "99999999999999999999999".to_owned()] {
            let mut request = format!("POST /pair-setup HTTP/1.1\r\nContent-Length: {length}\r\n\r\n").into_bytes();
            assert!(parse_request(&mut request).is_err(), "length {length}");
        }
    }

    /// A bridge on a free local port with small limits, its state in a
    /// directory of its own.
    async fn bridge(name: &str, slots: usize, idle: Duration) -> (Bridge, Arc<Store>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("hm-server-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::open(dir.join("state.json")).unwrap());
        let config = Config {
            name: "Test".into(),
            model: "Test".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: false,
            snapshots: None,
        };
        let bridge = Bridge::start_with(config, store.clone(), Database::new(), slots, idle).await.unwrap();
        (bridge, store, dir)
    }

    /// Sends one request in the clear and returns the body of its answer.
    async fn ask(stream: &mut TcpStream, path: &str, body: &[u8]) -> Vec<u8> {
        let head = format!("POST {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len());
        stream.write_all(&[head.as_bytes(), body].concat()).await.unwrap();
        let mut answer = Vec::new();
        loop {
            if let Some(end) = answer.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&answer[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map_or(0, |n| n.trim().parse::<usize>().unwrap());
                if answer.len() >= end + 4 + length {
                    return answer[end + 4..end + 4 + length].to_vec();
                }
            }
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the bridge hung up in the middle of an answer");
            answer.extend_from_slice(&chunk[..n]);
        }
    }

    /// Whether the bridge closes the connection within `within`.
    async fn closes(stream: &mut TcpStream, within: Duration) -> bool {
        let mut chunk = [0u8; 64];
        matches!(tokio::time::timeout(within, stream.read(&mut chunk)).await, Ok(Ok(0)) | Ok(Err(_)))
    }

    /// Verifies as a controller the store already knows, the way an Apple
    /// device does at the start of every connection.
    async fn verify(stream: &mut TcpStream, store: &Store) {
        use crate::crypto::{hkdf, random, seal};
        use crate::tlv::{self, Tlv};
        use ed25519_dalek::Signer;
        let identity = ed25519_dalek::SigningKey::from_bytes(&random::<32>());
        store.add_pairing("controller", &identity.verifying_key().to_bytes(), true).unwrap();
        let secret = x25519_dalek::StaticSecret::from(random::<32>());
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();

        let first = Tlv::new().with(tlv::STATE, &[1]).with(tlv::PUBLIC_KEY, &public).encode();
        let answer = Tlv::decode(&ask(stream, "/pair-verify", &first).await).unwrap();
        let theirs: [u8; 32] = answer.get(tlv::PUBLIC_KEY).unwrap().try_into().unwrap();
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(theirs)).to_bytes();
        let key = hkdf(crate::labels::PAIR_VERIFY_ENCRYPT_SALT, crate::labels::PAIR_VERIFY_ENCRYPT_INFO, &shared);
        let signed = [&public[..], b"controller", &theirs[..]].concat();
        let inner = Tlv::new()
            .with(tlv::IDENTIFIER, b"controller")
            .with(tlv::SIGNATURE, &identity.sign(&signed).to_bytes())
            .encode();
        let third = Tlv::new().with(tlv::STATE, &[3]).with(tlv::ENCRYPTED_DATA, &seal(&key, b"PV-Msg03", &[], &inner)).encode();
        let answer = Tlv::decode(&ask(stream, "/pair-verify", &third).await).unwrap();
        assert_eq!((answer.get_u8(tlv::STATE), answer.get_u8(tlv::ERROR)), (Some(4), None));
    }

    #[tokio::test]
    async fn a_silent_stranger_is_dropped_and_a_verified_controller_is_not() {
        let idle = Duration::from_millis(800);
        let (bridge, store, dir) = bridge("idle", 8, idle).await;
        let mut silent = TcpStream::connect(bridge.local_addr).await.unwrap();
        let mut pairing = TcpStream::connect(bridge.local_addr).await.unwrap();
        let mut controller = TcpStream::connect(bridge.local_addr).await.unwrap();
        verify(&mut controller, &store).await;

        // Pairing takes several requests on a connection that has not
        // verified itself. Each one within the limit keeps it open, well
        // past the point where a silent one is gone.
        for _ in 0..12 {
            tokio::time::sleep(idle / 4).await;
            let refused = ask(&mut pairing, "/pair-setup", &[]).await;
            assert!(!refused.is_empty());
        }
        assert!(closes(&mut silent, Duration::from_millis(100)).await, "three limits have passed in silence");
        assert!(!closes(&mut controller, idle * 3).await, "a verified controller may be idle for as long as it likes");
        assert!(closes(&mut pairing, Duration::from_millis(100)).await, "and the stranger that stopped talking is gone too");
        let left = bridge.connections();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].controller.as_deref(), Some("controller"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn when_full_the_oldest_stranger_makes_way_but_no_verified_controller_does() {
        // The limit on silence is out of the way here.
        let (bridge, store, dir) = bridge("slots", 2, Duration::from_secs(600)).await;
        let mut controller = TcpStream::connect(bridge.local_addr).await.unwrap();
        verify(&mut controller, &store).await;
        let mut first = TcpStream::connect(bridge.local_addr).await.unwrap();
        ask(&mut first, "/identify", &[]).await;

        // Both slots are taken. A newcomer gets the stranger's.
        let mut second = TcpStream::connect(bridge.local_addr).await.unwrap();
        assert!(closes(&mut first, Duration::from_secs(5)).await, "the older stranger was not asked to go");
        ask(&mut second, "/identify", &[]).await;
        verify(&mut second, &store).await;

        // Now both are verified, and nobody makes way for a third.
        let mut third = TcpStream::connect(bridge.local_addr).await.unwrap();
        assert!(closes(&mut third, Duration::from_secs(5)).await, "a third connection was let in");
        assert!(!closes(&mut controller, Duration::from_millis(200)).await);
        assert!(!closes(&mut second, Duration::from_millis(200)).await);
        assert_eq!(bridge.connections().len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
