//! Exercises the client against a local stand-in for a UniFi console, with
//! a real TLS handshake and a freshly generated self-signed certificate.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use harbormaster_protect::{fetch_fingerprint, Client, Error, Fingerprint};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const BOOTSTRAP: &str = r#"{
    "nvr": {"id": "n1", "mac": "AABBCC", "name": "Test NVR", "version": "6.2.1", "type": "UNVR"},
    "cameras": [{"id": "c1", "mac": "001122", "name": "Front Door", "type": "UVC G4 Doorbell Pro",
                 "state": "CONNECTED", "videoCodec": "h264", "featureFlags": {"isDoorbell": true}}],
    "lastUpdateId": "u1"
}"#;

struct Console {
    port: u16,
    fingerprint: Fingerprint,
    /// HTTP requests that reached the server after a completed handshake.
    requests: Arc<AtomicUsize>,
}

/// How the stand-in answers sign-in and bootstrap requests.
#[derive(Clone, Copy)]
enum Behaviour {
    Normal,
    TwoFactor,
    NoProtect,
}

fn reply(status: &str, headers: &str, body: &str) -> String {
    format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

fn answer(request: &str, behaviour: Behaviour) -> String {
    let (head, body) = request.split_once("\r\n\r\n").unwrap_or((request, ""));
    let first = head.lines().next().unwrap_or("");
    let signed_in = head.lines().any(|l| l.eq_ignore_ascii_case("cookie: TOKEN=session-1"))
        && head.lines().any(|l| l.eq_ignore_ascii_case("x-csrf-token: csrf-1"));
    match (first, behaviour) {
        ("POST /api/auth/login HTTP/1.1", Behaviour::TwoFactor) => reply("499 MFA", "", "{}"),
        ("POST /api/auth/login HTTP/1.1", _) => {
            let json: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            if json["username"] == "harbormaster" && json["password"] == "correct horse" {
                reply(
                    "200 OK",
                    "Set-Cookie: OTHER=1; Path=/\r\nSet-Cookie: TOKEN=session-1; Path=/; HttpOnly\r\nX-CSRF-Token: csrf-1\r\n",
                    "{}",
                )
            } else {
                reply("401 Unauthorized", "", "{}")
            }
        }
        ("GET /proxy/protect/api/bootstrap HTTP/1.1", Behaviour::NoProtect) => {
            reply("200 OK", "Content-Type: text/html\r\n", "<!doctype html>")
        }
        ("GET /proxy/protect/api/bootstrap HTTP/1.1", _) if signed_in => {
            reply("200 OK", "Content-Type: application/json; charset=utf-8\r\n", BOOTSTRAP)
        }
        ("GET /proxy/protect/api/bootstrap HTTP/1.1", _) => reply("401 Unauthorized", "", "{}"),
        (line, _) if line.starts_with("GET /proxy/protect/api/cameras/c1/snapshot?") && signed_in => {
            let wants_size = line.contains("&w=640&h=480");
            reply("200 OK", "Content-Type: image/jpeg\r\n", if wants_size { "JPEG-640" } else { "JPEG" })
        }
        ("PATCH /proxy/protect/api/lights/l1 HTTP/1.1", _) if signed_in => {
            let json: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            if json == serde_json::json!({"lightOnSettings": {"isLedForceOn": true}}) {
                reply("200 OK", "Content-Type: application/json\r\n", "{}")
            } else {
                reply("400 Bad Request", "", "{}")
            }
        }
        ("PATCH /proxy/protect/api/lights/readonly HTTP/1.1", _) if signed_in => reply("403 Forbidden", "", "{}"),
        (line, _) if line.starts_with("GET /proxy/protect/api/cameras/c1/package-snapshot?") && signed_in => {
            reply("200 OK", "Content-Type: image/jpeg\r\n", "PACKAGE")
        }
        _ => reply("404 Not Found", "", "{}"),
    }
}

async fn start(behaviour: Behaviour) -> Console {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate: CertificateDer<'static> = cert.der().clone();
    let fingerprint = Fingerprint::of(&certificate);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = requests.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, seen) = (acceptor.clone(), seen.clone());
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else { return };
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = stream.read(&mut chunk).await else { return };
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&request);
                    let Some((head, body)) = text.split_once("\r\n\r\n") else { continue };
                    let expected: usize = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                        .unwrap_or(0);
                    if body.len() >= expected {
                        break;
                    }
                }
                seen.fetch_add(1, Ordering::SeqCst);
                let response = answer(&String::from_utf8_lossy(&request), behaviour);
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Console { port, fingerprint, requests }
}

#[tokio::test]
async fn signs_in_and_reads_inventory() {
    let console = start(Behaviour::Normal).await;
    let mut client = Client::new("localhost", console.port, console.fingerprint);
    assert!(matches!(client.bootstrap().await, Err(Error::NotSignedIn)));

    client.login("harbormaster", "correct horse").await.unwrap();
    let bootstrap = client.bootstrap().await.unwrap();
    assert_eq!(bootstrap.nvr.name.as_deref(), Some("Test NVR"));
    assert_eq!(bootstrap.cameras.len(), 1);
    assert_eq!(bootstrap.cameras[0].device.display_name(), "Front Door");
    assert!(bootstrap.cameras[0].feature_flags.is_doorbell);
}

#[tokio::test]
async fn reports_bad_credentials_and_two_factor_accounts() {
    let console = start(Behaviour::Normal).await;
    let mut client = Client::new("localhost", console.port, console.fingerprint);
    assert!(matches!(client.login("harbormaster", "wrong").await, Err(Error::BadCredentials)));
    assert!(matches!(client.bootstrap().await, Err(Error::NotSignedIn)));

    let console = start(Behaviour::TwoFactor).await;
    let mut client = Client::new("localhost", console.port, console.fingerprint);
    assert!(matches!(client.login("harbormaster", "correct horse").await, Err(Error::TwoFactorRequired)));
}

#[tokio::test]
async fn wrong_certificate_stops_before_credentials_are_sent() {
    let console = start(Behaviour::Normal).await;
    let impostor = start(Behaviour::Normal).await;
    // Pinned to one console's certificate but pointed at the other.
    let mut client = Client::new("localhost", impostor.port, console.fingerprint);
    let error = client.login("harbormaster", "correct horse").await.unwrap_err();
    assert!(matches!(error, Error::CertificateMismatch(_)), "{error}");
    assert!(error.to_string().contains(&impostor.fingerprint.to_string()), "{error}");
    assert_eq!(impostor.requests.load(Ordering::SeqCst), 0, "no request may reach an unpinned server");
}

#[tokio::test]
async fn reads_fingerprint_without_sending_a_request() {
    let console = start(Behaviour::Normal).await;
    assert_eq!(fetch_fingerprint("localhost", console.port).await.unwrap(), console.fingerprint);
    assert_eq!(console.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn console_without_protect_is_reported_clearly() {
    let console = start(Behaviour::NoProtect).await;
    let mut client = Client::new("localhost", console.port, console.fingerprint);
    client.login("harbormaster", "correct horse").await.unwrap();
    assert!(matches!(client.bootstrap().await, Err(Error::ProtectNotFound)));
}

#[tokio::test]
async fn unreachable_console_is_a_connect_error() {
    // A listener that is bound and immediately dropped leaves a closed port.
    let port = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let pin: Fingerprint = "00".repeat(32).parse().unwrap();
    let mut client = Client::new("127.0.0.1", port, pin);
    assert!(matches!(client.login("a", "b").await, Err(Error::Connect(_))));
}

#[tokio::test]
async fn fetches_snapshots_and_refuses_odd_camera_ids() {
    let console = start(Behaviour::Normal).await;
    let mut client = Client::new("localhost", console.port, console.fingerprint);
    assert!(matches!(client.snapshot("c1", 640, 480).await, Err(Error::NotSignedIn)));
    client.login("harbormaster", "correct horse").await.unwrap();
    assert_eq!(&client.snapshot("c1", 640, 480).await.unwrap()[..], b"JPEG-640");
    assert_eq!(&client.package_snapshot("c1", 640, 480).await.unwrap()[..], b"PACKAGE");
    assert!(matches!(client.package_snapshot("../x", 1, 1).await, Err(Error::Protocol(_))));
    let before = console.requests.load(Ordering::SeqCst);
    assert!(matches!(client.snapshot("../users", 1, 1).await, Err(Error::Protocol(_))));
    assert!(matches!(client.snapshot("", 1, 1).await, Err(Error::Protocol(_))));
    assert_eq!(console.requests.load(Ordering::SeqCst), before, "bad ids never reach the console");
    assert!(matches!(client.snapshot("missing", 1, 1).await, Err(Error::Status(_))));
}

#[tokio::test]
async fn changes_a_device_and_reports_refusals() {
    let console = start(Behaviour::Normal).await;
    let mut client = Client::new("localhost", console.port, console.fingerprint);
    let on = serde_json::json!({"lightOnSettings": {"isLedForceOn": true}});
    assert!(matches!(client.update_device("lights", "l1", &on).await, Err(Error::NotSignedIn)));
    client.login("harbormaster", "correct horse").await.unwrap();
    client.update_device("lights", "l1", &on).await.unwrap();
    assert!(matches!(client.update_device("lights", "readonly", &on).await, Err(Error::Forbidden)));
    assert!(matches!(client.update_device("lights", "missing", &on).await, Err(Error::Status(_))));
    let before = console.requests.load(Ordering::SeqCst);
    assert!(matches!(client.update_device("lights/../users", "l1", &on).await, Err(Error::Protocol(_))));
    assert!(matches!(client.update_device("lights", "../admin", &on).await, Err(Error::Protocol(_))));
    assert_eq!(console.requests.load(Ordering::SeqCst), before, "odd paths never reach the console");
}
