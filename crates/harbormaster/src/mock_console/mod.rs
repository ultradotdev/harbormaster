//! `harbormaster mock-console`: a pretend UniFi Protect console, for trying
//! a fresh install end to end without a real one.
//!
//! It serves what Harbormaster asks a console for, over TLS with a
//! certificate of its own: sign-in with one account, whose password the
//! person starting the mock chooses as it starts, the
//! inventory of a small invented site, the realtime update stream in the
//! console's binary format with motion, recognitions, doorbell rings and
//! sensor changes played from a script, live video and snapshots made by
//! ffmpeg from test patterns, and a speaker that listens and discards.
//!
//! It is a development aid, not a model of Protect: it answers only the
//! requests Harbormaster makes, in the shapes Harbormaster reads.

mod site;
mod video;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use harbormaster_protect::Fingerprint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::password::Secret;
use site::{Scene, Site, SCRIPT};

/// The one account the mock accepts. Its password is chosen each time the
/// mock starts and kept only in memory, so none is written anywhere.
pub const USERNAME: &str = "protect-mock";

/// Where the mock listens unless told otherwise.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:7443";

/// How long a request head or body may be.
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;

/// The mock's certificate and key.
pub struct Identity {
    certificate: CertificateDer<'static>,
    key: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "mock-protect.invalid".to_owned()])
                .context("making a certificate")?;
        Ok(Self { certificate: cert.der().clone(), key: signing_key.serialize_der() })
    }

    /// The identity kept in `dir`, made there the first time, so the
    /// fingerprint stays the same from one run of the mock to the next.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let (cert_path, key_path) = (dir.join("certificate.der"), dir.join("key.der"));
        if let (Ok(certificate), Ok(key)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
            return Ok(Self { certificate: CertificateDer::from(certificate), key });
        }
        crate::daemon::create_private_dir(dir)?;
        let identity = Self::generate()?;
        write_private(&key_path, &identity.key)?;
        write_private(&cert_path, &identity.certificate)?;
        Ok(identity)
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.certificate)
    }

    fn acceptor(&self) -> Result<tokio_rustls::TlsAcceptor> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("TLS versions")?
            .with_no_client_auth()
            .with_single_cert(vec![self.certificate.clone()], key)
            .context("the mock's certificate")?;
        Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(bytes)?;
    Ok(())
}

/// What a one-time feed address leads to.
enum Ticket {
    Feed { camera: String, lens: u8, width: u32, height: u32 },
    Talkback { camera: String },
}

struct Console {
    /// The password the one account signs in with.
    password: Secret,
    site: Mutex<Site>,
    updates: broadcast::Sender<Bytes>,
    sessions: Mutex<HashSet<String>>,
    tickets: Mutex<HashMap<String, Ticket>>,
    ffmpeg: Option<PathBuf>,
}

impl Console {
    fn publish(&self, packets: Vec<Vec<u8>>) {
        for packet in packets {
            // Nobody listening is fine: the inventory has the change too.
            let _ = self.updates.send(Bytes::from(packet));
        }
    }

    fn signed_in(&self, request: &Request) -> bool {
        let Some(cookies) = request.header("cookie") else { return false };
        let sessions = self.sessions.lock().unwrap();
        cookies
            .split(';')
            .filter_map(|pair| pair.trim().strip_prefix("TOKEN="))
            .any(|token| sessions.contains(token))
    }
}

/// A random token, as hex.
fn token() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .expect("reading /dev/urandom");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Serves the mock on `listener` until the process ends. `pace` sets how
/// quickly the script of events plays.
pub async fn serve(listener: TcpListener, identity: &Identity, password: Secret, pace: Duration) -> Result<()> {
    let acceptor = identity.acceptor()?;
    let console = Arc::new(Console {
        password,
        site: Mutex::new(Site::default()),
        updates: broadcast::channel(256).0,
        sessions: Mutex::default(),
        tickets: Mutex::default(),
        ffmpeg: crate::video::find_ffmpeg(),
    });
    if console.ffmpeg.is_none() {
        tracing::warn!("ffmpeg is not installed, so the mock's cameras have no video or snapshots");
    }
    tokio::spawn(simulate(console.clone(), pace));
    loop {
        let (tcp, peer) = listener.accept().await?;
        let (acceptor, console) = (acceptor.clone(), console.clone());
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(stream) => {
                    if let Err(e) = handle(console, stream).await {
                        tracing::debug!("{peer}: {e:#}");
                    }
                }
                // The bridge's certificate check only looks, then hangs up.
                Err(e) => tracing::debug!("{peer}: TLS: {e}"),
            }
        });
    }
}

/// Plays the script over and over.
async fn simulate(console: Arc<Console>, pace: Duration) {
    let mut round = 0;
    loop {
        for scene in SCRIPT {
            tokio::time::sleep(pace).await;
            if !matches!(scene, Scene::Weather) {
                tracing::info!("{}", scene.describe());
            }
            let packets = scene.start(&mut console.site.lock().unwrap(), round);
            console.publish(packets);
            tokio::time::sleep(pace).await;
            let packets = scene.end(&mut console.site.lock().unwrap());
            console.publish(packets);
        }
        round += 1;
    }
}

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn query_number(&self, key: &str) -> u32 {
        self.query.get(key).and_then(|v| v.parse().ok()).unwrap_or(0)
    }

    fn wants_websocket(&self) -> bool {
        self.header("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
    }
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Request> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        if buffer.len() > MAX_HEAD {
            bail!("request head too long");
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before a request");
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (method, target) = (first.next().unwrap_or_default().to_owned(), first.next().unwrap_or_default());
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key.to_owned(), value.to_owned())
        })
        .collect();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers.iter().find(|(n, _)| n == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    if length > MAX_BODY {
        bail!("request body too long");
    }
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed in the middle of a request");
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Ok(Request { method, path: path.to_owned(), query, headers, body })
}

struct Reply {
    status: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn json(status: &'static str, body: &Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "application/json; charset=utf-8".into())],
            body: body.to_string().into_bytes(),
        }
    }

    fn error(status: &'static str) -> Self {
        Self::json(status, &json!({"error": status}))
    }
}

async fn send_reply<S: AsyncWrite + Unpin>(stream: &mut S, reply: Reply) -> Result<()> {
    let mut head = format!("HTTP/1.1 {}\r\n", reply.status);
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", reply.body.len()));
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&reply.body).await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(console: Arc<Console>, mut stream: S) -> Result<()> {
    let request = read_request(&mut stream).await?;
    if request.method == "POST" && request.path == "/api/auth/login" {
        return send_reply(&mut stream, sign_in(&console, &request)).await;
    }
    if !console.signed_in(&request) {
        tracing::debug!("refused {} {}: not signed in", request.method, request.path);
        return send_reply(&mut stream, Reply::error("401 Unauthorized")).await;
    }
    if request.wants_websocket() {
        return websocket(console, stream, request).await;
    }
    let reply = answer(&console, &request).await;
    send_reply(&mut stream, reply).await
}

fn sign_in(console: &Console, request: &Request) -> Reply {
    let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
    let username = body["username"].as_str().unwrap_or_default();
    if username != USERNAME || body["password"].as_str() != Some(console.password.expose()) {
        // The name is the tester's own typing; the password is never shown.
        tracing::info!("refused a sign-in as \"{}\"", username.escape_debug());
        return Reply::json("401 Unauthorized", &json!({"code": "AUTHENTICATION_FAILED_INVALID_CREDENTIALS"}));
    }
    let session = token();
    console.sessions.lock().unwrap().insert(session.clone());
    tracing::info!("signed in \"{USERNAME}\"");
    let mut reply = Reply::json("200 OK", &json!({"username": USERNAME, "isOwner": false}));
    reply.headers.push(("Set-Cookie", format!("TOKEN={session}; Path=/; Secure; HttpOnly; SameSite=Strict")));
    reply.headers.push(("X-Updated-CSRF-Token", token()));
    reply
}

async fn answer(console: &Console, request: &Request) -> Reply {
    let parts: Vec<&str> = request.path.trim_start_matches('/').split('/').collect();
    match (request.method.as_str(), parts.as_slice()) {
        ("GET", ["proxy", "protect", "api", "bootstrap"]) => {
            Reply::json("200 OK", console.site.lock().unwrap().bootstrap())
        }
        ("GET", ["proxy", "protect", "api", "cameras", camera, which @ ("snapshot" | "package-snapshot")]) => {
            let lens = if *which == "snapshot" { 0 } else { site::PACKAGE_LENS };
            snapshot(console, camera, lens, request).await
        }
        ("PATCH", ["proxy", "protect", "api", section, id]) => {
            let changes: Value = match serde_json::from_slice(&request.body) {
                Ok(changes @ Value::Object(_)) => changes,
                _ => return Reply::error("400 Bad Request"),
            };
            let packets = console.site.lock().unwrap().patch(section, id, &changes);
            match packets {
                Some(packets) => {
                    tracing::info!("changed {section}/{id}: {changes}");
                    console.publish(packets);
                    Reply::json("200 OK", &json!({}))
                }
                None => Reply::error("404 Not Found"),
            }
        }
        ("GET", ["proxy", "protect", "api", "ws", "livestream"]) => mint_feed(console, request),
        ("GET", ["proxy", "protect", "api", "ws", "talkback"]) => {
            let camera = request.query.get("camera").cloned().unwrap_or_default();
            if !console.site.lock().unwrap().has_camera(&camera) {
                return Reply::error("404 Not Found");
            }
            let ticket = token();
            console.tickets.lock().unwrap().insert(ticket.clone(), Ticket::Talkback { camera });
            Reply::json("200 OK", &json!({"url": format!("wss://192.0.2.10:7442/ws/talkback?token={ticket}")}))
        }
        _ => {
            tracing::debug!("no answer for {} {}", request.method, request.path);
            Reply::error("404 Not Found")
        }
    }
}

async fn snapshot(console: &Console, camera: &str, lens: u8, request: &Request) -> Reply {
    if !console.site.lock().unwrap().has_camera(camera) {
        return Reply::error("404 Not Found");
    }
    let Some(ffmpeg) = &console.ffmpeg else { return Reply::error("503 Service Unavailable") };
    let (width, height) = video::tidy_size(request.query_number("w"), request.query_number("h"));
    match video::snapshot(ffmpeg, site::pattern(camera, lens), width, height).await {
        Some(jpeg) => Reply { status: "200 OK", headers: vec![("Content-Type", "image/jpeg".into())], body: jpeg },
        None => Reply::error("500 Internal Server Error"),
    }
}

/// Hands out a one-time address for a camera's live feed.
fn mint_feed(console: &Console, request: &Request) -> Reply {
    let camera = request.query.get("camera").cloned().unwrap_or_default();
    let lens = request.query_number("lens") as u8;
    let size = {
        let site = console.site.lock().unwrap();
        if lens == 0 { site.channel_size(&camera, request.query_number("channel")) } else { site.package_size(&camera) }
    };
    let Some((width, height)) = size else { return Reply::error("404 Not Found") };
    let ticket = token();
    console.tickets.lock().unwrap().insert(ticket.clone(), Ticket::Feed { camera, lens, width, height });
    // A real console names itself by an internal address here too.
    Reply::json("200 OK", &json!({"url": format!("wss://192.0.2.10:7442/ws/livestream?token={ticket}")}))
}

async fn websocket<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    console: Arc<Console>,
    mut stream: S,
    request: Request,
) -> Result<()> {
    enum Wanted {
        Updates,
        Ticket(Ticket),
    }
    let wanted = match request.path.as_str() {
        "/proxy/protect/ws/updates" => Some(Wanted::Updates),
        "/proxy/protect/ws/livestream" | "/proxy/protect/ws/talkback" => request
            .query
            .get("token")
            .and_then(|t| console.tickets.lock().unwrap().remove(t))
            .map(Wanted::Ticket),
        _ => None,
    };
    let (Some(wanted), Some(key)) = (wanted, request.header("sec-websocket-key")) else {
        return send_reply(&mut stream, Reply::error("404 Not Found")).await;
    };
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;
    let socket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    match wanted {
        Wanted::Updates => updates(&console, socket).await,
        Wanted::Ticket(Ticket::Feed { camera, lens, width, height }) => {
            let Some(ffmpeg) = console.ffmpeg.clone() else {
                let mut socket = socket;
                let _ = socket.close(None).await;
                return Ok(());
            };
            let label = format!("camera {camera} lens {lens}");
            video::feed(socket, ffmpeg, site::pattern(&camera, lens), width, height, label).await;
        }
        Wanted::Ticket(Ticket::Talkback { camera }) => talkback(socket, &camera).await,
    }
    Ok(())
}

/// Sends every update from now on, until the client goes away.
async fn updates<S: AsyncRead + AsyncWrite + Unpin>(console: &Console, mut socket: WebSocketStream<S>) {
    let mut feed = console.updates.subscribe();
    tracing::info!("update stream opened");
    loop {
        tokio::select! {
            packet = feed.recv() => match packet {
                Ok(packet) => {
                    if socket.send(Message::Binary(packet)).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => tracing::warn!("a slow client missed {missed} updates"),
                Err(broadcast::error::RecvError::Closed) => break,
            },
            message = socket.next() => match message {
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
    tracing::info!("update stream closed");
}

/// Takes whatever a viewer says through a camera and lets it go.
async fn talkback<S: AsyncRead + AsyncWrite + Unpin>(mut socket: WebSocketStream<S>, camera: &str) {
    let mut heard = 0usize;
    tracing::info!("camera {camera}: speaker opened");
    while let Some(Ok(message)) = socket.next().await {
        match message {
            Message::Binary(audio) => heard += audio.len(),
            Message::Close(_) => break,
            _ => {}
        }
    }
    tracing::info!("camera {camera}: speaker closed after {} kB of sound", heard / 1024);
}

/// Asks the person starting the mock which password it should accept.
fn choose_password(from_stdin: bool) -> Result<Secret> {
    if from_stdin {
        return crate::tty::read_stdin();
    }
    for _ in 0..3 {
        let first = crate::tty::read_password(&format!("Choose a password for the mock's \"{USERNAME}\" account: "))?;
        if first.is_empty() {
            println!("The password cannot be empty.");
            continue;
        }
        let again = crate::tty::read_password("The same password again: ")?;
        if again.expose() == first.expose() {
            return Ok(first);
        }
        println!("Those were not the same.");
    }
    bail!("no password was chosen")
}

/// The `mock-console` command.
pub fn run(state_dir: &Path, listen: SocketAddr, from_stdin: bool) -> Result<()> {
    // On a clean machine this may run before setup has made the state
    // directory, which must be the owner's alone like everything in it.
    crate::daemon::create_private_dir(state_dir)?;
    let identity = Identity::load_or_create(&state_dir.join("mock-console"))?;
    let password = choose_password(from_stdin)?;
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = TcpListener::bind(listen).await.with_context(|| format!("listening on {listen}"))?;
        let address = listener.local_addr()?;
        let host = if address.ip().is_unspecified() { "this Mac's address".to_owned() } else { address.ip().to_string() };
        println!(
            "\nA mock UniFi Protect console is listening on {address}.\n\
             It is not a real console: it serves an invented site for testing Harbormaster.\n\n\
             \x20   address:     {host}:{port}\n\
             \x20   fingerprint: {fingerprint}\n\
             \x20   username:    {USERNAME}\n\
             \x20   password:    the one you just chose\n\n\
             In another terminal, run `harbormaster setup` and give it those answers.\n\
             Press Ctrl-C to stop.\n",
            port = address.port(),
            fingerprint = identity.fingerprint(),
        );
        serve(listener, &identity, password, Duration::from_secs(3)).await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use harbormaster_protect::{Client, Error, FeedOptions, Segment};

    /// Starts a mock that accepts a password made up on the spot, and
    /// returns where it is, its fingerprint and that password.
    async fn start(pace: Duration) -> (u16, Fingerprint, String) {
        let identity = Identity::generate().unwrap();
        let fingerprint = identity.fingerprint();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let chosen = token();
        let password = Secret::new(chosen.clone());
        tokio::spawn(async move { serve(listener, &identity, password, pace).await });
        (port, fingerprint, chosen)
    }

    #[tokio::test]
    async fn the_client_signs_in_reads_the_site_and_hears_what_happens() {
        let (port, fingerprint, password) = start(Duration::from_millis(50)).await;
        assert_eq!(harbormaster_protect::fetch_fingerprint("127.0.0.1", port).await.unwrap(), fingerprint);

        let mut client = Client::new("127.0.0.1", port, fingerprint);
        assert!(matches!(client.bootstrap().await, Err(Error::NotSignedIn)));
        let wrong: String = password.chars().rev().collect();
        assert!(matches!(client.login(USERNAME, &wrong).await, Err(Error::BadCredentials)));
        assert!(matches!(client.login(&format!("{USERNAME}2"), &password).await, Err(Error::BadCredentials)));
        // A client that pins some other certificate sends nothing.
        let mut stranger = Client::new("127.0.0.1", port, Fingerprint::of(b"another console"));
        assert!(matches!(stranger.login(USERNAME, &password).await, Err(Error::CertificateMismatch(_))));

        client.login(USERNAME, &password).await.unwrap();
        let bootstrap = client.bootstrap().await.unwrap();
        assert_eq!(bootstrap.nvr.name.as_deref(), Some("Mock Protect"));
        assert_eq!((bootstrap.cameras.len(), bootstrap.lights.len(), bootstrap.sensors.len()), (4, 1, 3));
        assert!(bootstrap.cameras[0].feature_flags.is_doorbell);

        let mut updates = client.updates(bootstrap.last_update_id.as_deref()).await.unwrap();
        let mut seen = HashSet::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !["event", "camera", "sensor", "light"].iter().all(|k| seen.contains(*k)) {
            let update = tokio::time::timeout_at(deadline, updates.next()).await.expect("updates kept coming").unwrap().unwrap();
            seen.insert(update.model_key);
        }

        // A change asked for comes back as an update, as on a real console.
        client.update_device("lights", site::FLOODLIGHT, &json!({"lightOnSettings": {"isLedForceOn": true}})).await.unwrap();
        loop {
            let update = tokio::time::timeout_at(deadline, updates.next()).await.unwrap().unwrap().unwrap();
            if update.model_key == "light" && update.data["lightOnSettings"]["isLedForceOn"] == true {
                assert_eq!(update.data["isLightOn"], true);
                break;
            }
        }
        assert!(matches!(client.update_device("lights", "nothing", &json!({})).await, Err(Error::Status(_))));

        let mut speaker = client.talkback(site::PORCH).await.unwrap();
        speaker.send(Bytes::from_static(b"hello")).await.unwrap();
    }

    #[tokio::test]
    async fn cameras_give_live_video_and_snapshots_when_ffmpeg_is_installed() {
        if crate::video::find_ffmpeg().is_none() {
            eprintln!("skipping: ffmpeg is not installed");
            return;
        }
        let (port, fingerprint, password) = start(Duration::from_secs(60)).await;
        let mut client = Client::new("127.0.0.1", port, fingerprint);
        client.login(USERNAME, &password).await.unwrap();

        let jpeg = client.snapshot(site::DRIVEWAY, 320, 180).await.unwrap();
        assert!(jpeg.starts_with(&[0xFF, 0xD8]));
        assert!(client.package_snapshot(site::PORCH, 320, 240).await.unwrap().starts_with(&[0xFF, 0xD8]));

        for options in [FeedOptions { channel: 1, ..FeedOptions::default() }, FeedOptions { lens: site::PACKAGE_LENS, ..FeedOptions::default() }] {
            let mut feed = client.livestream(site::PORCH, options).await.unwrap();
            let wait = Duration::from_secs(20);
            let Segment::Init { data, .. } = tokio::time::timeout(wait, feed.next()).await.unwrap().unwrap().unwrap() else {
                panic!("the header comes first")
            };
            assert!(crate::fmp4::video_track(&data).is_some());
            let Segment::Media(fragment) = tokio::time::timeout(wait, feed.next()).await.unwrap().unwrap().unwrap() else {
                panic!("then media")
            };
            assert!(crate::fmp4::has_keyframe(&fragment, crate::fmp4::video_track(&data).unwrap()));
        }
        assert!(matches!(client.livestream("nothing", FeedOptions::default()).await, Err(Error::Status(_))));
    }

    #[test]
    fn the_identity_is_kept_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("hm-mock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = Identity::load_or_create(&dir).unwrap().fingerprint();
        assert_eq!(Identity::load_or_create(&dir).unwrap().fingerprint(), first);
        for file in ["certificate.der", "key.der"] {
            assert_eq!(std::fs::metadata(dir.join(file)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
