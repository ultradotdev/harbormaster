//! Client for UniFi Protect's local (private) API.
//!
//! Everything goes to the console on the local network over TLS pinned to
//! the console's own certificate. Nothing here talks to Ubiquiti's cloud.

mod client;
pub mod model;
mod tls;

pub use client::{Client, Error};
pub use tls::{fetch_fingerprint, BadFingerprint, Fingerprint};
