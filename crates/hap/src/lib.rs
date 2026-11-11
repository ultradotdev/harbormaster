//! A small HomeKit Accessory Protocol server for IP accessories and bridges.
//!
//! This crate owns the security-critical core of Harbormaster: pairing,
//! session encryption, the accessory database and the HTTP endpoints that
//! Apple controllers talk to.

mod crypto;
mod mdns;
pub mod model;
mod pairing;
mod server;
mod session;
mod srp;
pub mod store;
mod tlv;

pub use model::{Accessory, Characteristic, Database, Format, Info};
pub use server::{Bridge, Config, ConnectionInfo, Error};
pub use store::Store;
