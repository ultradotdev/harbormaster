//! The HomeKit accessory server: a small HTTP/1.1 server whose connections
//! switch to an encrypted transport once a controller has verified itself.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch, Semaphore};

use crate::mdns::Advertiser;
use crate::model::{status, Change, Database};
use crate::pairing::{self, SetupState, VerifyState};
use crate::session::Session;
use crate::store::Store;

/// Largest request (headers plus body) a controller may send.
const MAX_REQUEST: usize = 64 * 1024;
/// Simultaneous controller connections. Each Apple device in the home holds
/// one open, so this needs headroom well beyond the protocol minimum of 8.
const MAX_CONNECTIONS: usize = 64;

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
}

/// A controller connection, for status displays.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub peer: SocketAddr,
    /// Pairing identifier, once the controller has verified itself.
    pub controller: Option<String>,
    pub connected_at: std::time::SystemTime,
}

struct Shared {
    connections: Mutex<BTreeMap<u64, ConnectionInfo>>,
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

    /// Currently open controller connections, oldest first.
    pub fn connections(&self) -> Vec<ConnectionInfo> {
        self.shared.connections.lock().unwrap().values().cloned().collect()
    }

    pub async fn start(config: Config, store: Arc<Store>, db: Arc<Database>) -> Result<Self, Error> {
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
            connections: Mutex::new(BTreeMap::new()),
            store,
            db,
            failed_setup_attempts: AtomicU32::new(0),
            advertiser: Mutex::new(advertiser),
            pairings_changed: watch::channel(0).0,
        });

        let accept_shared = shared.clone();
        let task = tokio::spawn(async move {
            let shared = accept_shared;
            let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
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
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    tracing::warn!("connection limit reached, refusing {peer}");
                    continue;
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
                    shared.connections.lock().unwrap().insert(id, info);
                    let result = Connection::new(shared.clone(), stream, id, peer).run().await;
                    shared.connections.lock().unwrap().remove(&id);
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
        .filter(|n| header_len + n <= MAX_REQUEST)
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
    session: Option<Session>,
    /// Identifier of the verified controller, once pair-verify has succeeded.
    controller: Option<String>,
    setup: SetupState,
    verify: Option<VerifyState>,
    subscriptions: HashSet<(u64, u64)>,
}

impl Connection {
    fn new(shared: Arc<Shared>, stream: TcpStream, id: u64, peer: SocketAddr) -> Self {
        Self {
            shared,
            stream,
            id,
            peer,
            session: None,
            controller: None,
            setup: SetupState::default(),
            verify: None,
            subscriptions: HashSet::new(),
        }
    }

    async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match &mut self.session {
            Some(session) => self.stream.write_all(&session.encrypt(bytes)).await,
            None => self.stream.write_all(bytes).await,
        }
    }

    async fn run(mut self) -> Result<(), ConnectionError> {
        let mut changes = self.shared.db.subscribe_changes();
        let mut pairings = self.shared.pairings_changed.subscribe();
        let (mut raw, mut plain) = (Vec::new(), Vec::new());
        let mut chunk = [0u8; 4096];
        loop {
            tokio::select! {
                read = self.stream.read(&mut chunk) => {
                    let n = read?;
                    if n == 0 {
                        return Ok(());
                    }
                    match &mut self.session {
                        Some(session) => {
                            raw.extend_from_slice(&chunk[..n]);
                            session.decrypt(&mut raw, &mut plain)?;
                        }
                        None => plain.extend_from_slice(&chunk[..n]),
                    }
                    while let Some(request) = parse_request(&mut plain)? {
                        let was_encrypted = self.session.is_some();
                        let (reply, upgrade) = self.handle(request);
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
    fn handle(&mut self, request: Request) -> (Vec<u8>, Option<Session>) {
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
                if verified.is_none() {
                    self.log_pairing_step("pair-verify", &request.body, &body);
                }
                let session = verified.map(|v| {
                    tracing::debug!("connection {} verified as {}", self.id, v.controller_id);
                    if let Some(info) = self.shared.connections.lock().unwrap().get_mut(&self.id) {
                        info.controller = Some(v.controller_id.clone());
                    }
                    self.controller = Some(v.controller_id);
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
            ("GET", "/accessories", Some(_)) => json_response(200, &self.shared.db.to_json()),
            ("GET", "/characteristics", Some(_)) => self.read_characteristics(&request.query),
            ("PUT", "/characteristics", Some(_)) => self.write_characteristics(&request.body),
            // Timed writes are acknowledged; no characteristic requires them yet.
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
        let mut results = Vec::new();
        for write in writes {
            let (Some(aid), Some(iid)) = (write["aid"].as_u64(), write["iid"].as_u64()) else {
                return bad();
            };
            let mut code = status::OK;
            if let Some(value) = write.get("value") {
                if let Err(e) = self.shared.db.write(aid, iid, value, self.id) {
                    code = e;
                }
            }
            if let (status::OK, Some(subscribe)) = (code, write.get("ev")) {
                match (self.shared.db.with(aid, iid, |c| c.notifies), subscribe.as_bool()) {
                    (None, _) => code = status::NOT_FOUND,
                    (Some(false), _) => code = status::NO_NOTIFICATIONS,
                    (Some(true), Some(true)) => {
                        self.subscriptions.insert((aid, iid));
                    }
                    (Some(true), Some(false)) => {
                        self.subscriptions.remove(&(aid, iid));
                    }
                    (Some(true), None) => code = status::INVALID_VALUE,
                }
            }
            failed |= code != status::OK;
            results.push(json!({ "aid": aid, "iid": iid, "status": code }));
        }
        if failed {
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
}
