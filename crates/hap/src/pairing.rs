//! The three pairing endpoints: pair-setup (one-time, proves knowledge of the
//! setup code and exchanges long-term keys), pair-verify (every connection,
//! establishes session keys), and pairings (add, remove, list controllers).
//!
//! Each handler takes a TLV8 request body and returns a TLV8 response body.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{from_hex, hkdf, open, random, seal};
use crate::srp::SrpServer;
use crate::store::Store;
use crate::tlv::{self, error, Tlv};

/// Failed setup-code attempts allowed before pairing locks until restart.
const MAX_SETUP_ATTEMPTS: u32 = 100;

fn fail(state: u8, code: u8) -> Vec<u8> {
    Tlv::new().with(tlv::STATE, &[state]).with(tlv::ERROR, &[code]).encode()
}

fn key32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_bytes(public_key), Signature::from_slice(signature))
    else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}

/// Per-connection pair-setup progress.
#[derive(Default)]
pub enum SetupState {
    #[default]
    Idle,
    /// M2 sent; waiting for the controller's proof.
    Started(SrpServer),
    /// M4 sent; waiting for the controller's long-term key.
    Proven([u8; 64]),
}

pub fn pair_setup(
    state: &mut SetupState,
    store: &Store,
    failed_attempts: &std::sync::atomic::AtomicU32,
    body: &[u8],
) -> Vec<u8> {
    use std::sync::atomic::Ordering;
    let Ok(req) = Tlv::decode(body) else { return fail(0, error::UNKNOWN) };
    match (req.get_u8(tlv::STATE), std::mem::take(state)) {
        (Some(1), _) => {
            if store.is_paired() {
                return fail(2, error::UNAVAILABLE);
            }
            if failed_attempts.load(Ordering::Relaxed) >= MAX_SETUP_ATTEMPTS {
                return fail(2, error::MAX_TRIES);
            }
            let srp = SrpServer::new("Pair-Setup", &store.setup_code());
            let response = Tlv::new()
                .with(tlv::STATE, &[2])
                .with(tlv::PUBLIC_KEY, srp.public_key())
                .with(tlv::SALT, srp.salt())
                .encode();
            *state = SetupState::Started(srp);
            response
        }
        (Some(3), SetupState::Started(srp)) => {
            let (Some(a_pub), Some(proof)) = (req.get(tlv::PUBLIC_KEY), req.get(tlv::PROOF)) else {
                return fail(4, error::UNKNOWN);
            };
            let Some((accessory_proof, key)) = srp.verify(a_pub, proof) else {
                failed_attempts.fetch_add(1, Ordering::Relaxed);
                return fail(4, error::AUTHENTICATION);
            };
            *state = SetupState::Proven(key);
            Tlv::new().with(tlv::STATE, &[4]).with(tlv::PROOF, &accessory_proof).encode()
        }
        (Some(5), SetupState::Proven(srp_key)) => {
            exchange_keys(store, &srp_key, &req).unwrap_or_else(|code| fail(6, code))
        }
        (Some(n @ (3 | 5)), _) => fail(n + 1, error::UNKNOWN),
        _ => fail(0, error::UNKNOWN),
    }
}

/// Pair-setup M5/M6: verify and store the controller's long-term key, then
/// return ours, both under a key derived from the SRP session.
fn exchange_keys(store: &Store, srp_key: &[u8; 64], req: &Tlv) -> Result<Vec<u8>, u8> {
    let session_key = hkdf(b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info", srp_key);
    let plain = req
        .get(tlv::ENCRYPTED_DATA)
        .and_then(|data| open(&session_key, b"PS-Msg05", &[], data))
        .ok_or(error::AUTHENTICATION)?;
    let inner = Tlv::decode(&plain).map_err(|_| error::UNKNOWN)?;
    let controller_id = inner.get(tlv::IDENTIFIER).ok_or(error::UNKNOWN)?;
    let controller_key = inner.get(tlv::PUBLIC_KEY).and_then(key32).ok_or(error::UNKNOWN)?;
    let signature = inner.get(tlv::SIGNATURE).ok_or(error::UNKNOWN)?;
    let controller_name = std::str::from_utf8(controller_id).map_err(|_| error::UNKNOWN)?;

    let mut signed =
        hkdf(b"Pair-Setup-Controller-Sign-Salt", b"Pair-Setup-Controller-Sign-Info", srp_key).to_vec();
    signed.extend_from_slice(controller_id);
    signed.extend_from_slice(&controller_key);
    if !verify_signature(&controller_key, &signed, signature) {
        return Err(error::AUTHENTICATION);
    }
    // Another connection may have completed pairing while this one ran.
    if store.is_paired() {
        return Err(error::UNAVAILABLE);
    }
    store.add_pairing(controller_name, &controller_key, true).map_err(|e| {
        tracing::error!("could not save pairing: {e}");
        error::UNKNOWN
    })?;

    let signing_key = store.signing_key();
    let device_id = store.device_id();
    let public_key = signing_key.verifying_key().to_bytes();
    let mut signed =
        hkdf(b"Pair-Setup-Accessory-Sign-Salt", b"Pair-Setup-Accessory-Sign-Info", srp_key).to_vec();
    signed.extend_from_slice(device_id.as_bytes());
    signed.extend_from_slice(&public_key);
    let inner = Tlv::new()
        .with(tlv::IDENTIFIER, device_id.as_bytes())
        .with(tlv::PUBLIC_KEY, &public_key)
        .with(tlv::SIGNATURE, &signing_key.sign(&signed).to_bytes())
        .encode();
    Ok(Tlv::new()
        .with(tlv::STATE, &[6])
        .with(tlv::ENCRYPTED_DATA, &seal(&session_key, b"PS-Msg06", &[], &inner))
        .encode())
}

/// Pair-verify progress between M2 and M3.
pub struct VerifyState {
    shared: [u8; 32],
    session_key: [u8; 32],
    accessory_public: [u8; 32],
    controller_public: [u8; 32],
}

/// A successfully verified controller and the secret its session derives from.
pub struct Verified {
    pub controller_id: String,
    pub shared_secret: [u8; 32],
}

pub fn pair_verify(
    state: &mut Option<VerifyState>,
    store: &Store,
    body: &[u8],
) -> (Vec<u8>, Option<Verified>) {
    let Ok(req) = Tlv::decode(body) else { return (fail(0, error::UNKNOWN), None) };
    match (req.get_u8(tlv::STATE), state.take()) {
        (Some(1), _) => {
            let Some(controller_public) = req.get(tlv::PUBLIC_KEY).and_then(key32) else {
                return (fail(2, error::UNKNOWN), None);
            };
            let secret = StaticSecret::from(random::<32>());
            let accessory_public = PublicKey::from(&secret).to_bytes();
            let shared = secret.diffie_hellman(&PublicKey::from(controller_public)).to_bytes();
            let session_key = hkdf(b"Pair-Verify-Encrypt-Salt", b"Pair-Verify-Encrypt-Info", &shared);

            let device_id = store.device_id();
            let mut signed = accessory_public.to_vec();
            signed.extend_from_slice(device_id.as_bytes());
            signed.extend_from_slice(&controller_public);
            let inner = Tlv::new()
                .with(tlv::IDENTIFIER, device_id.as_bytes())
                .with(tlv::SIGNATURE, &store.signing_key().sign(&signed).to_bytes())
                .encode();
            let response = Tlv::new()
                .with(tlv::STATE, &[2])
                .with(tlv::PUBLIC_KEY, &accessory_public)
                .with(tlv::ENCRYPTED_DATA, &seal(&session_key, b"PV-Msg02", &[], &inner))
                .encode();
            *state = Some(VerifyState { shared, session_key, accessory_public, controller_public });
            (response, None)
        }
        (Some(3), Some(v)) => match finish_verify(&v, store, &req) {
            Ok(controller_id) => (
                Tlv::new().with(tlv::STATE, &[4]).encode(),
                Some(Verified { controller_id, shared_secret: v.shared }),
            ),
            Err(reason) => {
                // An unknown identity is routine: Apple devices try pairings
                // they remember from before the bridge was last added to a
                // home, then retry. A bad signature is not routine.
                match reason {
                    VerifyFailure::UnknownController => {
                        tracing::debug!("pair-verify refused: controller identity is not paired")
                    }
                    VerifyFailure::Malformed => tracing::warn!("pair-verify refused: malformed or undecryptable request"),
                    VerifyFailure::BadSignature => {
                        tracing::warn!("pair-verify refused: a paired controller identity sent a bad signature")
                    }
                }
                (fail(4, error::AUTHENTICATION), None)
            }
        },
        (Some(3), None) => (fail(4, error::UNKNOWN), None),
        _ => (fail(0, error::UNKNOWN), None),
    }
}

enum VerifyFailure {
    Malformed,
    UnknownController,
    BadSignature,
}

fn finish_verify(v: &VerifyState, store: &Store, req: &Tlv) -> Result<String, VerifyFailure> {
    use VerifyFailure::*;
    let sealed = req.get(tlv::ENCRYPTED_DATA).ok_or(Malformed)?;
    let plain = open(&v.session_key, b"PV-Msg03", &[], sealed).ok_or(Malformed)?;
    let inner = Tlv::decode(&plain).map_err(|_| Malformed)?;
    let controller_id =
        inner.get(tlv::IDENTIFIER).and_then(|id| std::str::from_utf8(id).ok()).ok_or(Malformed)?;
    let signature = inner.get(tlv::SIGNATURE).ok_or(Malformed)?;
    let pairing = store.pairing(controller_id).ok_or(UnknownController)?;
    let public_key = from_hex(&pairing.public_key).and_then(|k| key32(&k)).ok_or(Malformed)?;

    let mut signed = v.controller_public.to_vec();
    signed.extend_from_slice(controller_id.as_bytes());
    signed.extend_from_slice(&v.accessory_public);
    if verify_signature(&public_key, &signed, signature) {
        Ok(controller_id.to_owned())
    } else {
        Err(BadSignature)
    }
}

/// Add, remove or list pairings. Only admin controllers may call this.
pub fn pairings(store: &Store, caller_id: &str, body: &[u8]) -> Vec<u8> {
    let Ok(req) = Tlv::decode(body) else { return fail(2, error::UNKNOWN) };
    if !store.pairing(caller_id).is_some_and(|p| p.admin) {
        return fail(2, error::AUTHENTICATION);
    }
    let ok = || Tlv::new().with(tlv::STATE, &[2]);
    let target = req.get(tlv::IDENTIFIER).and_then(|id| std::str::from_utf8(id).ok());
    let saved = |result: Result<(), crate::store::StoreError>| match result {
        Ok(()) => ok().encode(),
        Err(e) => {
            tracing::error!("could not save pairings: {e}");
            fail(2, error::UNKNOWN)
        }
    };
    match req.get_u8(tlv::METHOD) {
        // Add pairing
        Some(3) => {
            let (Some(id), Some(key), Some(permissions)) = (
                target,
                req.get(tlv::PUBLIC_KEY).and_then(key32),
                req.get_u8(tlv::PERMISSIONS),
            ) else {
                return fail(2, error::UNKNOWN);
            };
            match store.pairing(id) {
                // Re-adding an existing controller may only change its permissions.
                Some(existing) if from_hex(&existing.public_key).as_deref() != Some(&key[..]) => {
                    fail(2, error::UNKNOWN)
                }
                _ => saved(store.add_pairing(id, &key, permissions & 1 == 1)),
            }
        }
        // Remove pairing
        Some(4) => match target {
            Some(id) => saved(store.remove_pairing(id)),
            None => fail(2, error::UNKNOWN),
        },
        // List pairings
        Some(5) => {
            let mut out = ok();
            for (i, (id, pairing)) in store.pairings().iter().enumerate() {
                if i > 0 {
                    out.push(tlv::SEPARATOR, &[]);
                }
                out.push(tlv::IDENTIFIER, id.as_bytes());
                out.push(tlv::PUBLIC_KEY, &from_hex(&pairing.public_key).unwrap_or_default());
                out.push(tlv::PERMISSIONS, &[pairing.admin as u8]);
            }
            out.encode()
        }
        _ => fail(2, error::UNKNOWN),
    }
}
