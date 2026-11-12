//! Client for UniFi Protect's local (private) API.
//!
//! Everything goes to the console on the local network over TLS pinned to
//! the console's own certificate. Nothing here talks to Ubiquiti's cloud.

mod client;
mod livestream;
pub mod model;
mod tls;
mod updates;

pub use client::{Client, Error, Talkback};
pub use livestream::{Decoder, FeedError, FeedOptions, FrameCounts, Livestream, Segment};
pub use tls::{fetch_fingerprint, BadFingerprint, Fingerprint};
pub use updates::{decode_packet, DecodeError, Update, UpdateStream};
