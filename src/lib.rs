use std::{error::Error, fmt};

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, constants::ED25519_BASEPOINT_POINT};
use rand_core::{RngCore, CryptoRng, OsRng};

use sha2::{Sha256, Digest};



pub struct Signer {
    internal_secret: Scalar,
    key: Scalar,
}

impl Signer {
    pub fn new<T: RngCore + CryptoRng>(key: Scalar, mut csprng: T) -> Signer{
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);

        Signer {
            internal_secret: Scalar::from_bytes_mod_order(bytes),
            key
        }
    }

    pub fn sign(&self, msg: Vec<EdwardsPoint>) -> Signature{
        todo!()
    }

    fn hash(digest: Vec<EdwardsPoint>) -> Scalar{
        let v: Vec<[u8;32]> = digest.iter().map(|p| edpoint_to_bytes(*p)).collect();
    
        let mut hasher = <Sha256 as Digest>::new();
        for tab in v {
            hasher.update(tab.as_slice());
        }
    
        let result = hasher.finalize();
        println!("Binary hash: {:?}", result);
        Scalar::from_bytes_mod_order(result.into())
    }
}

pub struct Signature {
    c: EdwardsPoint,
    z: Scalar,
}



/// Generate a random scalar
pub fn random_scalar<T: RngCore + CryptoRng>(mut csprng: T) -> Scalar {
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

/// Generate a random `EdwardPoint`
pub fn generate_keypair() -> (Scalar, EdwardsPoint) {
    let r_scalar = random_scalar(OsRng);
    (r_scalar, r_scalar * ED25519_BASEPOINT_POINT)
}

pub fn edpoint_to_bytes(edp: EdwardsPoint) -> [u8;32] {
    edp.to_montgomery().to_bytes()
}

pub fn hash(digest: Vec<EdwardsPoint>) -> Scalar{
    let v: Vec<[u8;32]> = digest.iter().map(|p| edpoint_to_bytes(*p)).collect();

    let mut hasher = <Sha256 as Digest>::new();
    for tab in v {
        hasher.update(tab.as_slice());
    }

    let result = hasher.finalize();
    println!("Binary hash: {:?}", result);
    Scalar::from_bytes_mod_order(result.into())
}

pub fn sign(c: Scalar, secret_key: Scalar, random: Scalar) -> Scalar {
    random + c*secret_key
}

pub fn verify(z: Scalar, c: Scalar, pub_key: EdwardsPoint, X: EdwardsPoint, Y: EdwardsPoint) -> bool{
    let r = z*ED25519_BASEPOINT_POINT - c*pub_key;

    let c_prime = hash(vec![r, ED25519_BASEPOINT_POINT, pub_key, X, Y]);

    c.eq(&c_prime)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sign_verify(){
        let (x,X) = generate_keypair();
        let (y,Y) = generate_keypair();
        let (r,R) = generate_keypair();

        let (b_sk, b_pk) = generate_keypair();

        let c = hash(vec![R, ED25519_BASEPOINT_POINT, b_pk, X, Y]);

        let z = sign(c, b_sk, r);

        assert!(verify(z, c, b_pk, X, Y));
    }
}