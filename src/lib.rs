mod signature;
mod signing;
mod helpers;
mod verifying;
mod keys;

pub use crate::verifying::*;
pub use crate::signing::*;
pub use crate::signature::*;
pub use crate::keys::*;

#[cfg(test)]
mod tests {
    use curve25519_dalek::{Scalar, EdwardsPoint, constants::ED25519_BASEPOINT_POINT};
    use rand_core::OsRng;

    use crate::{helpers::random_scalar, signing::{SigningKey, Signer}, verifying::VerifyingKey, PublicKey, SecretKey};
    
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
    fn diffie_hellman_verify(){
        let petit_x = SecretKey::random_from_rng(OsRng);
        let grand_x = PublicKey::from(&petit_x);
        let petit_y = SecretKey::random_from_rng(OsRng);
        let grand_y = PublicKey::from(&petit_y);

        let shared_secret_x = petit_x.diffie_hellman(&grand_y);
        let shared_secret_y = petit_y.diffie_hellman(&grand_x);

        println!("x shared secret : {:?}", shared_secret_x.to_tab());
        println!("y shared secret : {:?}", shared_secret_y.to_tab());

        assert_eq!(shared_secret_x.as_byte(),shared_secret_y.as_byte());
    }
}

