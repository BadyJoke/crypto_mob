use std::{error::Error, fmt};

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, constants::ED25519_BASEPOINT_POINT};
use rand_core::{RngCore, CryptoRng, OsRng};

use sha2::{Sha256, Digest};

#[derive(Debug)]
pub struct SignatureError;

impl Error for SignatureError {}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Verification equation was not satisfied")
    }
}

pub struct SigningKey {
    secret_key: Scalar,
    public_key: EdwardsPoint
}

impl SigningKey {
    pub fn generate<T: RngCore + CryptoRng>(mut csprng: T) -> SigningKey {
        let r = random_scalar(csprng);
        SigningKey { secret_key: r, public_key: random_edward_point(r) }
    }
}

pub trait Signer {
    fn sign(&self, msg: &mut Vec<EdwardsPoint>) -> Signature;
}

impl Signer for SigningKey {

    fn sign(&self, msg: &mut Vec<EdwardsPoint>) -> Signature{
        let r = random_scalar(OsRng);
        let mut digest = vec![random_edward_point(r), ED25519_BASEPOINT_POINT, self.public_key];
        digest.append(msg);
        let c = hash(digest);

        let z = r + c * self.secret_key;

        Signature { c, z }

    }
}

pub struct Signature {
    c: Scalar,
    z: Scalar,
}

pub struct Verifier {
    key: EdwardsPoint,
}

impl Verifier {
    pub fn verify(&self, msg: &mut Vec<EdwardsPoint>, signature: &Signature) -> Result<(), SignatureError> {
        let R = signature.z * ED25519_BASEPOINT_POINT - signature.c * self.key;
        let mut digest = vec![R, ED25519_BASEPOINT_POINT, self.key];
        digest.append(msg);
        let c = hash(digest);

        match signature.c.eq(&c) {
            true => Ok(()),
            false => Err(SignatureError),
        }
    }
}


/// Generate a random scalar
pub fn random_scalar<T: RngCore + CryptoRng>(mut csprng: T) -> Scalar {
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

/// Generate a random `EdwardPoint`
pub fn random_edward_point(r: Scalar) -> EdwardsPoint {
    r * ED25519_BASEPOINT_POINT
}

/// Generate a keypair
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
        
    }
}