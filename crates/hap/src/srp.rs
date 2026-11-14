//! Accessory (server) side of SRP-6a as HomeKit uses it: the RFC 5054
//! 3072-bit group, generator 5, SHA-512, with public values left-padded to
//! the modulus length.

use num_bigint::BigUint;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

use crate::crypto::random;

const N_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

/// Byte length of the modulus and of every padded public value.
pub const KEY_LEN: usize = 384;

fn modulus() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("modulus constant is valid hex")
}

fn pad(n: &BigUint) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    let mut out = vec![0u8; KEY_LEN.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

fn hash(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// k = H(N | PAD(g))
fn multiplier(n: &BigUint, g: &BigUint) -> BigUint {
    BigUint::from_bytes_be(&hash(&[&n.to_bytes_be(), &pad(g)]))
}

pub struct SrpServer {
    username: String,
    salt: [u8; 16],
    verifier: BigUint,
    b: BigUint,
    b_pub: Vec<u8>,
}

impl SrpServer {
    pub fn new(username: &str, password: &str) -> Self {
        Self::with_secrets(username, password, random(), &random::<32>())
    }

    fn with_secrets(username: &str, password: &str, salt: [u8; 16], b: &[u8]) -> Self {
        let n = modulus();
        let g = BigUint::from(5u8);
        let inner = hash(&[username.as_bytes(), b":", password.as_bytes()]);
        let x = BigUint::from_bytes_be(&hash(&[&salt, &inner]));
        let verifier = g.modpow(&x, &n);
        let b = BigUint::from_bytes_be(b);
        let b_pub = (multiplier(&n, &g) * &verifier + g.modpow(&b, &n)) % &n;
        Self { username: username.to_owned(), salt, verifier, b, b_pub: pad(&b_pub) }
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// The accessory's public value B, padded to [`KEY_LEN`].
    pub fn public_key(&self) -> &[u8] {
        &self.b_pub
    }

    /// Checks the controller's public value and proof. On success returns the
    /// accessory proof M2 and the 64-byte session key K.
    pub fn verify(&self, a_pub: &[u8], client_proof: &[u8]) -> Option<([u8; 64], [u8; 64])> {
        let n = modulus();
        let g = BigUint::from(5u8);
        let a = BigUint::from_bytes_be(a_pub);
        // A mod N == 0 would let anyone force a known session key.
        if a_pub.len() > KEY_LEN || (&a % &n) == BigUint::ZERO {
            return None;
        }
        let a_padded = pad(&a);
        let u = BigUint::from_bytes_be(&hash(&[&a_padded, &self.b_pub]));
        let secret = (&a * self.verifier.modpow(&u, &n)).modpow(&self.b, &n);
        let key = hash(&[&pad(&secret)]);

        let h_n = hash(&[&n.to_bytes_be()]);
        let h_g = hash(&[&g.to_bytes_be()]);
        let group: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(a, b)| a ^ b).collect();
        let expected = hash(&[
            &group,
            &hash(&[self.username.as_bytes()]),
            &self.salt,
            &a_padded,
            &self.b_pub,
            &key,
        ]);
        if expected.ct_eq(client_proof).unwrap_u8() != 1 {
            return None;
        }
        Some((hash(&[&a_padded, &expected, &key]), key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplier_matches_known_homekit_constant() {
        let k = multiplier(&modulus(), &BigUint::from(5u8));
        let hex: String = k.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "a9c2e2559bf0ebb53f0cbbf62282906bede7f2182f00678211fbd5bde5b28503\
             3a4993503b87397f9be5ec02080fedbc0835587ad039060879b8621e8c3659e0"
        );
    }

    /// Minimal controller side, used only to check the server agrees with it.
    fn client_proof(
        user: &str,
        pass: &str,
        salt: &[u8],
        b_pub: &[u8],
        a_secret: &[u8],
    ) -> (Vec<u8>, [u8; 64], [u8; 64]) {
        let n = modulus();
        let g = BigUint::from(5u8);
        let a = BigUint::from_bytes_be(a_secret);
        let a_pub = pad(&g.modpow(&a, &n));
        let x = BigUint::from_bytes_be(&hash(&[
            salt,
            &hash(&[user.as_bytes(), b":", pass.as_bytes()]),
        ]));
        let u = BigUint::from_bytes_be(&hash(&[&a_pub, b_pub]));
        let k = multiplier(&n, &g);
        let b = BigUint::from_bytes_be(b_pub);
        // (B - k*g^x) mod N, kept non-negative.
        let base = (&b + &n * &k - (&k * g.modpow(&x, &n)) % (&n * &k)) % &n;
        let secret = base.modpow(&(&a + &u * &x), &n);
        let key = hash(&[&pad(&secret)]);
        let h_n = hash(&[&n.to_bytes_be()]);
        let h_g = hash(&[&g.to_bytes_be()]);
        let group: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(a, b)| a ^ b).collect();
        let m1 = hash(&[&group, &hash(&[user.as_bytes()]), salt, &a_pub, b_pub, &key]);
        (a_pub, m1, key)
    }

    /// A setup code made for this run, in the shape HomeKit uses. Nothing
    /// in these tests depends on a particular code, so none is written down.
    fn setup_code() -> String {
        let digits: String = crate::crypto::random::<8>().iter().map(|b| char::from(b'0' + b % 10)).collect();
        format!("{}-{}-{}", &digits[..3], &digits[3..5], &digits[5..])
    }

    #[test]
    fn accepts_correct_password_and_rejects_wrong_one() {
        let code = setup_code();
        let server = SrpServer::with_secrets(
            "Pair-Setup",
            &code,
            crate::crypto::random::<16>(),
            &crate::crypto::random::<32>(),
        );
        let ours = crate::crypto::random::<32>();
        let (a_pub, m1, key) = client_proof("Pair-Setup", &code, server.salt(), server.public_key(), &ours);
        let (_m2, server_key) = server.verify(&a_pub, &m1).expect("proof should verify");
        assert_eq!(server_key, key);

        // The same code with its last digit changed.
        let last = code.as_bytes()[code.len() - 1] - b'0';
        let other = format!("{}{}", &code[..code.len() - 1], (last + 1) % 10);
        let (a_pub, m1, _) = client_proof("Pair-Setup", &other, server.salt(), server.public_key(), &ours);
        assert!(server.verify(&a_pub, &m1).is_none());
    }

    #[test]
    fn rejects_zero_public_value() {
        let server = SrpServer::new("Pair-Setup", &setup_code());
        assert!(server.verify(&[0u8; KEY_LEN], &[0u8; 64]).is_none());
        assert!(server.verify(&modulus().to_bytes_be(), &[0u8; 64]).is_none());
    }
}
