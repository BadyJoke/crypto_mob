mod signature;
mod signing;
mod helpers;
mod verifying;

pub use crate::verifying::*;
pub use crate::signing::*;
pub use crate::signature::*;

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
}