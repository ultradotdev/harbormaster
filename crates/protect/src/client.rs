//! Signing in to a UniFi console and reading Protect's device inventory.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, CONTENT_TYPE, COOKIE, HOST, SET_COOKIE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;

use crate::livestream::{self, FeedOptions, Livestream};
use crate::model::Bootstrap;
use crate::tls::{self, Fingerprint};
use crate::updates::UpdateStream;

/// Largest response accepted. Bootstrap documents for big sites run to a few
/// megabytes; this leaves generous room without being unbounded.
const MAX_RESPONSE: usize = 64 * 1024 * 1024;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not reach the console: {0}")]
    Connect(#[source] std::io::Error),
    #[error("the console's certificate does not match the pinned fingerprint ({0})")]
    CertificateMismatch(String),
    #[error("the console rejected the username or password")]
    BadCredentials,
    #[error("this account requires two-factor sign-in; use a local-only account instead")]
    TwoFactorRequired,
    #[error("too many sign-in attempts; the console is rate limiting this account")]
    RateLimited,
    #[error("not signed in, or the session expired")]
    NotSignedIn,
    #[error("the console refused: this account is not allowed to change devices")]
    Forbidden,
    #[error("UniFi Protect is not running on this console")]
    ProtectNotFound,
    #[error("the console answered {0}")]
    Status(StatusCode),
    #[error("the console did not answer within {} seconds", REQUEST_TIMEOUT.as_secs())]
    Timeout,
    #[error("unexpected response from the console: {0}")]
    Protocol(String),
}

struct Session {
    cookie: String,
    csrf_token: Option<String>,
}

pub struct Client {
    host: String,
    port: u16,
    pin: Fingerprint,
    session: Option<Session>,
}

impl Client {
    pub fn new(host: &str, port: u16, pin: Fingerprint) -> Self {
        Self { host: host.to_owned(), port, pin, session: None }
    }

    async fn send(&self, request: Request<Full<Bytes>>) -> Result<Response<Bytes>, Error> {
        let exchange = async {
            let stream = tls::connect(&self.host, self.port, self.pin).await.map_err(|e| {
                let text = e.to_string();
                if text.contains("fingerprint mismatch") {
                    Error::CertificateMismatch(text)
                } else {
                    Error::Connect(e)
                }
            })?;
            let protocol = |e: hyper::Error| Error::Protocol(e.to_string());
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(protocol)?;
            // Drives the connection; it ends when the response is complete.
            tokio::spawn(connection);
            let response = sender.send_request(request).await.map_err(protocol)?;
            let (parts, body) = response.into_parts();
            let body = Limited::new(body, MAX_RESPONSE)
                .collect()
                .await
                .map_err(|e| Error::Protocol(e.to_string()))?
                .to_bytes();
            Ok(Response::from_parts(parts, body))
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange).await.map_err(|_| Error::Timeout)?
    }

    fn request(&self, method: Method, path: &str, body: Bytes) -> Request<Full<Bytes>> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, self.host.as_str())
            // Ask for one response and a closed connection: each call uses its own.
            .header("connection", "close")
            .body(Full::new(body))
            .expect("request parts are valid");
        if let Some(session) = &self.session {
            let headers = request.headers_mut();
            if let Ok(cookie) = HeaderValue::from_str(&session.cookie) {
                headers.insert(COOKIE, cookie);
            }
            if let Some(Ok(token)) = session.csrf_token.as_deref().map(HeaderValue::from_str) {
                headers.insert("x-csrf-token", token);
            }
        }
        request
    }

    /// Signs in with a local console account.
    pub async fn login(&mut self, username: &str, password: &str) -> Result<(), Error> {
        self.session = None;
        let body = serde_json::json!({ "username": username, "password": password, "rememberMe": true });
        let mut request = self.request(Method::POST, "/api/auth/login", Bytes::from(body.to_string()));
        request.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let response = self.send(request).await?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => return Err(Error::BadCredentials),
            StatusCode::TOO_MANY_REQUESTS => return Err(Error::RateLimited),
            // The console answers 499 when the account needs a second factor.
            status if status.as_u16() == 499 => return Err(Error::TwoFactorRequired),
            status => return Err(Error::Status(status)),
        }
        let cookie = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|v| v.split(';').next())
            .find(|pair| pair.starts_with("TOKEN="))
            .ok_or_else(|| Error::Protocol("sign-in succeeded but no session cookie was set".into()))?
            .to_owned();
        let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let csrf_token = header("x-updated-csrf-token").or_else(|| header("x-csrf-token"));
        self.session = Some(Session { cookie, csrf_token });
        Ok(())
    }

    /// Reads Protect's full device inventory.
    pub async fn bootstrap(&self) -> Result<Bootstrap, Error> {
        let raw = self.bootstrap_raw().await?;
        serde_json::from_value(raw).map_err(|e| Error::Protocol(format!("bootstrap: {e}")))
    }

    /// The bootstrap document as the console sent it. It contains account
    /// details and access keys, so treat it as sensitive.
    pub async fn bootstrap_raw(&self) -> Result<serde_json::Value, Error> {
        if self.session.is_none() {
            return Err(Error::NotSignedIn);
        }
        let response = self.send(self.request(Method::GET, "/proxy/protect/api/bootstrap", Bytes::new())).await?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => return Err(Error::NotSignedIn),
            StatusCode::NOT_FOUND => return Err(Error::ProtectNotFound),
            status => return Err(Error::Status(status)),
        }
        // A console without Protect serves its web app here instead of JSON.
        let is_json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"));
        if !is_json {
            return Err(Error::ProtectNotFound);
        }
        serde_json::from_slice(response.body()).map_err(|e| Error::Protocol(format!("bootstrap: {e}")))
    }

    /// A current still image from a camera, as JPEG. The console scales it
    /// to about the requested size.
    pub async fn snapshot(&self, camera_id: &str, width: u32, height: u32) -> Result<Bytes, Error> {
        self.still(camera_id, "snapshot", width, height).await
    }

    /// A current still from a doorbell's downward-facing package camera.
    pub async fn package_snapshot(&self, camera_id: &str, width: u32, height: u32) -> Result<Bytes, Error> {
        self.still(camera_id, "package-snapshot", width, height).await
    }

    async fn still(&self, camera_id: &str, which: &str, width: u32, height: u32) -> Result<Bytes, Error> {
        if self.session.is_none() {
            return Err(Error::NotSignedIn);
        }
        // Ids are hex strings; refuse anything that could alter the path.
        if camera_id.is_empty() || !camera_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Error::Protocol("unexpected characters in camera id".into()));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let path = format!(
            "/proxy/protect/api/cameras/{camera_id}/{which}?ts={now}&force=true&w={width}&h={height}"
        );
        let response = self.send(self.request(Method::GET, &path, Bytes::new())).await?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => return Err(Error::NotSignedIn),
            status => return Err(Error::Status(status)),
        }
        let is_jpeg = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("image/jpeg"));
        if !is_jpeg {
            return Err(Error::Protocol("snapshot was not a JPEG image".into()));
        }
        Ok(response.into_body())
    }

    /// Changes settings of one device. `kind` is the console's plural name
    /// for the sort of device (`lights`, `cameras`, ...) and `changes` holds
    /// only the fields to change. This is the one call that alters anything
    /// on the console.
    pub async fn update_device(&self, kind: &str, id: &str, changes: &serde_json::Value) -> Result<(), Error> {
        if self.session.is_none() {
            return Err(Error::NotSignedIn);
        }
        // Both become part of the request path; refuse anything that could alter it.
        let plain = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric());
        if !plain(kind) || !plain(id) {
            return Err(Error::Protocol("unexpected characters in device kind or id".into()));
        }
        let path = format!("/proxy/protect/api/{kind}/{id}");
        let mut request = self.request(Method::PATCH, &path, Bytes::from(changes.to_string()));
        request.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let response = self.send(request).await?;
        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::UNAUTHORIZED => Err(Error::NotSignedIn),
            StatusCode::FORBIDDEN => Err(Error::Forbidden),
            status => Err(Error::Status(status)),
        }
    }

    /// Opens the realtime update stream. Pass the bootstrap's
    /// `last_update_id` so nothing is missed between the two.
    pub async fn updates(&self, last_update_id: Option<&str>) -> Result<UpdateStream, Error> {
        if self.session.is_none() {
            return Err(Error::NotSignedIn);
        }
        let mut url = format!("wss://{}:{}/proxy/protect/ws/updates", self.host, self.port);
        if let Some(id) = last_update_id {
            // Update ids are UUIDs; refuse anything that would need escaping.
            if !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(Error::Protocol("unexpected characters in update id".into()));
            }
            url.push_str("?lastUpdateId=");
            url.push_str(id);
        }
        Ok(UpdateStream::new(self.websocket(url, "update stream").await?))
    }

    /// Opens a camera's native live video feed.
    pub async fn livestream(&self, camera_id: &str, options: FeedOptions) -> Result<Livestream, Error> {
        if self.session.is_none() {
            return Err(Error::NotSignedIn);
        }
        if camera_id.is_empty() || !camera_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Error::Protocol("unexpected characters in camera id".into()));
        }
        // The console first hands out a one-time address for the feed.
        let path = format!("/proxy/protect/api/ws/livestream?{}", livestream::query(camera_id, options));
        let response = self.send(self.request(Method::GET, &path, Bytes::new())).await?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => return Err(Error::NotSignedIn),
            status => return Err(Error::Status(status)),
        }
        let answer: serde_json::Value =
            serde_json::from_slice(response.body()).map_err(|e| Error::Protocol(format!("live feed: {e}")))?;
        let minted = answer["url"]
            .as_str()
            .and_then(livestream::path_of)
            .ok_or_else(|| Error::Protocol("live feed: the console gave no usable address".into()))?;
        let url = format!("wss://{}:{}/proxy/protect{minted}", self.host, self.port);
        Ok(Livestream::new(self.websocket(url, "live feed").await?))
    }

    /// Opens a WebSocket to the pinned console with the session attached.
    async fn websocket(&self, url: String, what: &str) -> Result<WebSocketStream<TlsStream<TcpStream>>, Error> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let session = self.session.as_ref().ok_or(Error::NotSignedIn)?;
        let protocol = |e: &dyn std::fmt::Display| Error::Protocol(format!("{what}: {e}"));
        let mut request = url.into_client_request().map_err(|e| protocol(&e))?;
        request.headers_mut().insert(COOKIE, HeaderValue::from_str(&session.cookie).map_err(|e| protocol(&e))?);

        let connect = async {
            let stream = tls::connect(&self.host, self.port, self.pin).await.map_err(|e| {
                let text = e.to_string();
                if text.contains("fingerprint mismatch") {
                    Error::CertificateMismatch(text)
                } else {
                    Error::Connect(e)
                }
            })?;
            use tokio_tungstenite::tungstenite::Error as Ws;
            match tokio_tungstenite::client_async(request, stream).await {
                Ok((socket, _)) => Ok(socket),
                Err(Ws::Http(response)) if matches!(response.status().as_u16(), 401 | 403) => Err(Error::NotSignedIn),
                Err(e) => Err(protocol(&e)),
            }
        };
        tokio::time::timeout(REQUEST_TIMEOUT, connect).await.map_err(|_| Error::Timeout)?
    }
}
