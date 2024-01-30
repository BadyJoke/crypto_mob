use rand_core::{RngCore, CryptoRng, OsRng};

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, constants::ED25519_BASEPOINT_POINT};
use crate::helpers::{hash, random_scalar, random_edward_point};
use crate::signature::*;

pub struct w_h_H {
    pub w: Vec<EdwardPoint>,
    h: Scalar,
    pub H: EdwardPoint,
}

impl w_h_H {
    pub fn set_w(&self, my_pub: &EdwardsPoint, his_pub: &EdwardsPoint, auth_pub: &EdwardsPoint) {
        self.w = Vec::new();
        self.w.push(my_pub.clone());
        self.w.push(his_pub.clone());
        self.w.push(auth_pub.clone());
    }

    pub fn set_h(auth1: &EdwardsPoint, auth2: &EdwardsPoint, auth3: &EdwardsPoint){
        self.h = auth1 + auth2 + auth3;
    }
}



// ed25519 signing key for the other kind of signature
pub struct SigningKey2 {
    secret_key: Scalar,
    pub public_r1: EdwardsPoint,
    pub public_r2: EdwardsPoint,
}


impl SigningKey2 {
    /// Generate an ed25519 signing key.
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand_os::OsRng`.
    pub fn generate<T: RngCore + CryptoRng>(csprng: T, h_calculated: &EdwardsPoint, his_pub: &EdwardPoint) -> SigningKey2 {
        let r = random_scalar(csprng);
        let R1 = random_edward_point(r);
        let R2 = r*(h_calculated+his_pub);
        SigningKey2 { secret_key: r1, public_r1: R1, public_r2: R2}
    }
}

pub trait Signer2 {
    /// Sign a message and returns a `Signature`
    fn sign2(&self, structure: &w_h_H, his_pub: EdwardPoint, my_pub: &EdwardPoint) -> Signature;
}

impl Signer2 for SigningKey2 {
    fn sign(&self, structure: &w_h_H, his_pub: &EdwardPoint, my_pub: &EdwardPoint) -> Signature{
        let mut digest = vec![self.public_r1.clone(), self.public_r2.clone(), ED25519_BASEPOINT_POINT];
        let h_plus_hisPub = w_h_H.h.clone() + his_pub.clone();
        digest.append(h_plus_hisPub.clone());
        digest.append(my_pub.clone());
        digest.append(w_h_H.H.clone());
        digest.append(w_h_H.w.clone());
        let c = hash(digest);
        let z = r + c * self.secret_key;
        Signature { c, z }
    }
}


