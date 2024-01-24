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
    pub(crate) c: Scalar,
    pub(crate) z: Scalar,
}