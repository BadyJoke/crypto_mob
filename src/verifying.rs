use curve25519_dalek::{edwards::EdwardsPoint, constants::ED25519_BASEPOINT_POINT};

use crate::{signature::{Signature, SignatureError}, helpers::hash};


/// ed25519 key used to verify signatures
pub struct VerifyingKey {
    pub key: EdwardsPoint,
}

impl VerifyingKey {
    /// Verify a message 
    pub fn verify(&self, msg: &Vec<EdwardsPoint>, signature: &Signature) -> Result<(), SignatureError> {
        let r = signature.z * ED25519_BASEPOINT_POINT - signature.c * self.key;
        let mut digest = vec![r, ED25519_BASEPOINT_POINT, self.key];
        digest.append(msg.clone().as_mut());
        let c = hash(digest);

        match signature.c.eq(&c) {
            true => Ok(()),
            false => Err(SignatureError),
        }
    }
}

impl From<EdwardsPoint> for VerifyingKey {
    fn from(value: EdwardsPoint) -> Self {
        VerifyingKey { key: value }
    }
}