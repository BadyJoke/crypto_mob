use rand_core::{RngCore, CryptoRng};
use curve25519_dalek::{Scalar, EdwardsPoint, constants::ED25519_BASEPOINT_POINT};
use sha2::{Sha256, Digest};

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

