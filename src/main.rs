use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, constants::ED25519_BASEPOINT_POINT};
use rand_core::{RngCore, CryptoRng, OsRng};

use sha2::{Sha256, Digest};

/// Generate a random scalar
fn random_scalar<T: RngCore + CryptoRng>(mut csprng: T) -> Scalar {
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

/// Generate a random `EdwardPoint`
fn random_point() -> EdwardsPoint {
    let r_scalar = random_scalar(OsRng);
    r_scalar * ED25519_BASEPOINT_POINT
}

fn edpoint_to_bytes(edp: EdwardsPoint) -> [u8;32] {
    edp.to_montgomery().to_bytes()
}

fn hash(digest: Vec<EdwardsPoint>){
    let v: Vec<[u8;32]> = digest.iter().map(|p| edpoint_to_bytes(*p)).collect();

    let mut hasher = <Sha256 as Digest>::new();
    for tab in v {
        hasher.update(tab.as_slice());
    }

    let result = hasher.finalize();
    println!("Binary hash: {:?}", result);
}

fn main() {
    let R = random_point();
    let g = ED25519_BASEPOINT_POINT;

    let b_pk = random_point();

    let v: Vec<EdwardsPoint> = vec![R, g, b_pk];

    hash(v);
}
