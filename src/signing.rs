use rand_core::{RngCore, CryptoRng, OsRng};

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, constants::ED25519_BASEPOINT_POINT};
use crate::helpers::{hash, random_scalar, random_edward_point};
use crate::signature::*;

/// ed25519 signing key used to produce signatures 
pub struct SigningKey {
    /// Private half of the signing key
    secret_key: Scalar,
    /// Public half of the signing key
    pub public_key: EdwardsPoint,
}


// ed25519 signing key for the other kind of signature
pub struct SigningKey2 {
    secret_key: Scalar,
    pub public_r1: EdwardsPoint,
    pub public_r2: EdwardsPoint,
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
}

/// Sign the provided message bytestring using `Self`
/// returning a digital signature.
pub trait Signer {
    /// Sign a message and returns a `Signature`
    fn sign(&self, msg: &Vec<EdwardsPoint>) -> Signature;
}

impl Signer for SigningKey {
    fn sign(&self, msg: &Vec<EdwardsPoint>) -> Signature{
        let r = random_scalar(OsRng);
        let mut digest = vec![random_edward_point(r), ED25519_BASEPOINT_POINT, self.public_key];
        digest.append(msg.clone().as_mut());
        let c = hash(digest);

        let z = r + c * self.secret_key;

        Signature { c, z }
    }
}