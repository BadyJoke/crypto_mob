use curve25519_dalek::{edwards::EdwardsPoint, constants::ED25519_BASEPOINT_POINT};

use crate::{signature::{Signature, SignatureError}, helpers::hash};

/// ed25519 key used to verify signatures
pub struct VerifyingKnowledge {
    pub w: Vec<EdwardsPoint>,
    pub h: EdwardsPoint,
    pub big_h: EdwardsPoint,
}

impl VerifyingKnowledge {
    /// Verify a message 
    pub fn verify_knowledge(&self, signature: &Signature, his_message_pub : EdwardsPoint, my_message_pub : EdwardsPoint) -> Result<(), SignatureError> {
        let r1 = signature.z * ED25519_BASEPOINT_POINT - signature.c * my_message_pub;
        let r2 = signature.z *(self.h + his_message_pub) - signature.c * self.big_h;
        let mut digest = vec![r1, r2, ED25519_BASEPOINT_POINT, (self.h + his_message_pub), my_message_pub, self.big_h];
        digest.append(self.w.clone().as_mut());
        
        let c = hash(digest);

        match signature.c.eq(&c) {
            true => Ok(()),
            false => Err(SignatureError),
        }
    }
}