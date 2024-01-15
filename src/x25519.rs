use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint, scalar::Scalar};
use rand_core::{RngCore, CryptoRng};

pub struct PublicKey(pub(crate) MontgomeryPoint);

use curve25519_dalek::edwards::CompressedEdwardsY;

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn from_tab(tab: [u8; 32]) -> Self {
        let compressed = CompressedEdwardsY(tab);
        let edwards_point = compressed.decompress().expect("Invalid compressed point");
        PublicKey(edwards_point.to_montgomery())
    }

    pub fn get_scalar(&self) -> Scalar {
        let public_tab = self.as_bytes().clone();
        let public_scalar: Scalar = Scalar::from_bytes_mod_order(public_tab);
        public_scalar
    }

    pub fn to_edwards_point(&self) -> EdwardsPoint {
        let scalar = self.get_scalar();
        let scalar_bytes = scalar.to_bytes();
        let mut scalar_array = [0u8; 32];
        scalar_array.copy_from_slice(&scalar_bytes);
        
        EdwardsPoint::mul_base_clamped(scalar_array)
    }

}

impl<'a> From<&'a EphemeralSecret> for PublicKey {
    fn from(secret: &'a EphemeralSecret) -> Self {
        PublicKey(EdwardsPoint::mul_base_clamped(secret.0).to_montgomery())
    }
}

pub struct SharedSecret(pub(crate) MontgomeryPoint);

impl SharedSecret {
    pub fn as_byte(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn get_scalar(&self) -> Scalar {
        let secret_tab = self.as_byte().clone(); 
        let secret_scalar: Scalar = Scalar::from_bytes_mod_order(secret_tab);
        secret_scalar
    }
}

pub struct EphemeralSecret(pub(crate) [u8; 32]);

impl EphemeralSecret {
    /*
    pub fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(their_public.0.mul_clamped(self.0))
    }
    */

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(their_public.0.mul_clamped(self.0))
    }

    pub fn random_from_rng<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        EphemeralSecret(bytes)
    }

    pub fn from_tab(tab: [u8;32]) -> Self {
        EphemeralSecret(tab)
    }

    pub fn to_tab(&self) -> [u8; 32] {
        self.0
    }

    pub fn get_scalar(&self) -> Scalar {
        let secret_tab = self.to_tab();
        let secret_scalar: Scalar = Scalar::from_bytes_mod_order(secret_tab);
        secret_scalar
    }

    pub fn from_scalar(scalar: &Scalar) -> EphemeralSecret {
        let scalar_bytes = scalar.to_bytes();
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&scalar_bytes[..32]);
        EphemeralSecret(secret_bytes)
    }

    pub fn to_edwards_point(&self) -> EdwardsPoint {
        let scalar = self.get_scalar();
        let scalar_bytes = scalar.to_bytes();
        let mut scalar_array = [0u8; 32];
        scalar_array.copy_from_slice(&scalar_bytes);
        
        EdwardsPoint::mul_base_clamped(scalar_array)
    }

}