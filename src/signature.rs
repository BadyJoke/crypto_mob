use std::{error::Error, fmt};
use curve25519_dalek::Scalar;

/// Error type for signature related errors
#[derive(Debug)]
pub struct SignatureError;

impl Error for SignatureError {}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Verification equation was not satisfied")
    }
}

/// An ed25519 signature 
pub struct Signature {
    pub c: Scalar,
    pub z: Scalar,
}

impl Signature{
    pub fn from_existing_c_z(existing_c: Scalar, existing_z: Scalar) -> Signature{
        Signature{c: existing_c, z: existing_z}
    }

    pub fn from_c_z_bytes(c: [u8;32], z: [u8;32]) -> Signature{
        Signature {
            c: Scalar::from_canonical_bytes(c).unwrap(),
            z: Scalar::from_canonical_bytes(z).unwrap(),
        }
    }
}