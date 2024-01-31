use rand_core::{RngCore, CryptoRng, OsRng};

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, constants::ED25519_BASEPOINT_POINT};
use crate::helpers::{edpoint_to_bytes, hash, random_edward_point, random_scalar};
use crate::signature::*;

/// ed25519 signing key used to produce signatures 
pub struct SigningKey {
    /// Private half of the signing key
    pub secret_key: Scalar,
    /// Public half of the signing key
    pub public_key: EdwardsPoint,
}

impl SigningKey {
    /// Generate an ed25519 signing key.
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand_os::OsRng`.
    pub fn generate<T: RngCore + CryptoRng>(csprng: T) -> SigningKey {
        let r = random_scalar(csprng);
        SigningKey { secret_key: r, public_key: random_edward_point(r) }
    }

    pub fn from_existing_key(existing_secret_key: Scalar, existing_public_key: EdwardsPoint) -> SigningKey{
        SigningKey{secret_key: existing_secret_key, public_key: existing_public_key}
    }
}

/// Sign the provided message bytestring using `Self`
/// returning a digital signature.
pub trait Signer {
    /// Sign a message and returns a `Signature`
    fn sign(&self, msg: &Vec<[u8;32]>) -> Signature;
}

impl Signer for SigningKey {
    fn sign(&self, msg: &Vec<[u8;32]>) -> Signature{
        let r = random_scalar(OsRng);
        let digest = vec![random_edward_point(r), ED25519_BASEPOINT_POINT, self.public_key];
        let mut v: Vec<[u8;32]> = digest.iter().map(|p| edpoint_to_bytes(*p)).collect();
        v.append(msg.clone().as_mut());
        let c = hash(v);

        let z = r + c * self.secret_key;

        Signature { c, z }
    }
}