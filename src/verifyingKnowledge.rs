use curve25519_dalek::{edwards::EdwardsPoint, constants::ED25519_BASEPOINT_POINT};

use crate::{signature::{Signature, SignatureError}, helpers::hash};
use crate::{}


/// ed25519 key used to verify signatures
pub struct VerifyingKnowledge {
    w: Vec<EdwardPoint>,
    h: EdwardPoint,
    pub H: EdwardPoint,
}

impl VerifyingKnowledge {
    /// Verify a message 
    pub fn verifyKnowledge(&self, signature: &Signature, his_message_pub : &EdwardPoint, my_message_pub : &EdwardPoint) -> Result<(), SignatureError> {
        let R1 = signature.z * ED25519_BASEPOINT_POINT - signature.c * my_message_pub;
        let R2 = signature.z *(self.h + his_message_pub) - signature.c * self.H;
        let mut digest = vec![R1, R2, ED25519_BASEPOINT_POINT, (self.h + his__signing_pub), my_message_pub, self.H, self.w];
        let c = hash(digest);

        match signature.c.eq(&c) {
            true => Ok(()),
            false => Err(SignatureError),
        }
    }
}

