//! TLS to a UniFi console, which presents a self-signed certificate.
//!
//! Rather than turning verification off, the console's certificate is pinned
//! by its SHA-256 fingerprint: a connection only proceeds, and credentials
//! are only ever sent, if the server presents exactly that certificate.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// SHA-256 of a certificate in DER form.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(certificate_der: &[u8]) -> Self {
        Self(Sha256::digest(certificate_der).into())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: Vec<String> = self.0.iter().map(|b| format!("{b:02X}")).collect();
        f.write_str(&hex.join(":"))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("a certificate fingerprint is 64 hex digits, optionally separated by colons")]
pub struct BadFingerprint;

impl FromStr for Fingerprint {
    type Err = BadFingerprint;

    fn from_str(s: &str) -> Result<Self, BadFingerprint> {
        let digits: Vec<u8> = s.bytes().filter(|b| *b != b':' && !b.is_ascii_whitespace()).collect();
        if digits.len() != 64 {
            return Err(BadFingerprint);
        }
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(digits.chunks(2)) {
            let text = std::str::from_utf8(pair).map_err(|_| BadFingerprint)?;
            *byte = u8::from_str_radix(text, 16).map_err(|_| BadFingerprint)?;
        }
        Ok(Self(out))
    }
}

#[derive(Debug)]
struct PinVerifier {
    /// `None` accepts any certificate. Only used to read a fingerprint;
    /// nothing is sent over such a connection.
    pin: Option<Fingerprint>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = Fingerprint::of(end_entity);
        match self.pin {
            Some(pin) if pin != presented => Err(rustls::Error::General(format!(
                "certificate fingerprint mismatch: the console presented {presented}"
            ))),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    // The handshake signatures still prove the server holds the private key
    // of the pinned certificate, so these are checked normally.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn connector(pin: Option<Fingerprint>) -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn connect_with(
    host: &str,
    port: u16,
    pin: Option<Fingerprint>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from(host.to_owned())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // A firewalled address would otherwise hang for over a minute.
    let attempt = async {
        let tcp = TcpStream::connect((host, port)).await?;
        tcp.set_nodelay(true)?;
        connector(pin).connect(name, tcp).await
    };
    tokio::time::timeout(CONNECT_TIMEOUT, attempt).await.unwrap_or_else(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("no answer from {host}:{port} within {} seconds", CONNECT_TIMEOUT.as_secs()),
        ))
    })
}

/// Opens a TLS connection that only succeeds if the server presents the
/// pinned certificate.
pub async fn connect(host: &str, port: u16, pin: Fingerprint) -> std::io::Result<TlsStream<TcpStream>> {
    connect_with(host, port, Some(pin)).await
}

/// Reads the fingerprint of whatever certificate the server presents,
/// without sending it anything. The caller decides whether to trust it.
pub async fn fetch_fingerprint(host: &str, port: u16) -> std::io::Result<Fingerprint> {
    let stream = connect_with(host, port, None).await?;
    let (_, session) = stream.get_ref();
    session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| Fingerprint::of(cert))
        .ok_or_else(|| std::io::Error::other("the server presented no certificate"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_parses_both_spellings_and_round_trips() {
        // Made here from a few bytes that are no certificate at all, so
        // that no real console's fingerprint sits in the source.
        let made_up = Fingerprint::of(b"not a real certificate");
        let colon = made_up.to_string();
        // Thirty-two pairs of capital hex digits with colons between.
        assert_eq!(colon.len(), 95);
        assert!(colon.split(':').all(|pair| pair.len() == 2 && pair.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))));
        let parsed: Fingerprint = colon.parse().unwrap();
        assert_eq!(parsed, made_up);
        assert_eq!(parsed.to_string(), colon);
        assert_eq!(colon.replace(':', "").to_lowercase().parse::<Fingerprint>().unwrap(), parsed);
        assert_eq!("F3:AF".parse::<Fingerprint>(), Err(BadFingerprint));
        assert_eq!("zz".repeat(32).parse::<Fingerprint>(), Err(BadFingerprint));
    }
}
