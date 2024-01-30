use curve25519_dalek::{EdwardsPoint, MontgomeryPoint, Scalar};
use rand_core::{CryptoRng, RngCore};

pub struct SecretKey(pub [u8; 32]);

impl SecretKey{

    pub fn random_from_rng<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        SecretKey(bytes)
    }

    pub fn diffie_hellman(self, their_public : &PublicKey) -> SharedSecret{
        SharedSecret(their_public.0.mul_clamped(self.0).to_montgomery())
    }

    pub fn to_scalar(&self) -> Scalar{
        Scalar::from_bytes_mod_order(self.0)
    }

    pub fn from_tab(tab: [u8;32]) -> Self {
        SecretKey(tab)
    }
}

pub struct Test(pub(crate) [u8;32]);
pub struct PublicKey(pub EdwardsPoint);

impl PublicKey {
    
    pub fn from(secret_key : &SecretKey) -> PublicKey{
        let r_edward = EdwardsPoint::mul_base_clamped(secret_key.0);
        PublicKey(r_edward)
    }

    pub fn to_tab(&self) -> [u8; 32] {
        self.0.to_montgomery().to_bytes()
    }
}

#[derive(Debug)]
pub struct SharedSecret(pub MontgomeryPoint);

impl SharedSecret {
    pub fn as_byte(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_tab(&self) -> [u8; 32] {
        *self.0.as_bytes()
    }
}
