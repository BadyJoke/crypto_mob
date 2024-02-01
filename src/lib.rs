mod signature;
mod signing;
mod helpers;
mod verifying;
mod signingknowledge;
mod verifyingknowledge;

pub use crate::verifying::*;
pub use crate::signing::*;
pub use crate::signature::*;

pub use crate::signingknowledge::*;
pub use crate::verifyingknowledge::*;

#[cfg(test)]
mod tests {
    use curve25519_dalek::{Scalar, EdwardsPoint, constants::ED25519_BASEPOINT_POINT};
    use rand_core::OsRng;

    use crate::{helpers::random_scalar, signing::{SigningKey, Signer}, verifying::VerifyingKey};
    
    /// Helping function to generate a keypair
    pub fn generate_keypair() -> (Scalar, EdwardsPoint) {
        let r_scalar = random_scalar(OsRng);
        (r_scalar, r_scalar * ED25519_BASEPOINT_POINT)
    }

    #[test]
    #[allow(non_snake_case)]
    fn sign_verify(){
        let sign_key = SigningKey::generate(OsRng);
        let (_, X) = generate_keypair();
        let (_, Y) = generate_keypair();

        let msg = vec![X, Y];

        let signature = sign_key.sign(&msg);

        let verif_key = VerifyingKey::from(sign_key.public_key);

        assert_eq!(verif_key.verify(&msg, &signature).unwrap(), ());
    }

    #[test]
    #[allow(non_snake_case)]
    fn knowledge_verify(){
        //keys for the message
        let (x, X) = generate_keypair();
        let (y, Y) = generate_keypair();

        //keys for Alice and Bob
        let (B_sec, B_pub) = generate_keypair();
        let (A_sec, A_pub) = generate_keypair();

        let (_, auth1_pub) = generate_keypair();
        let (_, auth2_pub) = generate_keypair();
        let (_, auth3_pub) = generate_keypair();

        let w = vec![B_pub,A_pub,auth1_pub,auth2_pub,auth3_pub];
        let h = auth1_pub + auth2_pub + auth3_pub;
        let H = y * (h+X);

        let knowledgeElements = crate::signingknowledge::KnowledgeElements{
            w: w,
            h: h,
            big_h: H,
        };

        //knowledge verification
        let knowledgeSignature = knowledgeElements.sign_knowledge(X,Y,y);

        let verifyKnowledge = crate::verifyingknowledge::VerifyingKnowledge{
            w: w,
            h: h,
            big_h: H,
        };

        assert_eq!(verifyKnowledge.verify_knowledge(knowledgeSignature,X,Y).unwrap(),());

    }
}