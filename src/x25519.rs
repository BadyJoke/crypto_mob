use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint};
use rand_core::{RngCore, CryptoRng};

pub struct PublicKey(pub(crate) MontgomeryPoint);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
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
}

pub struct EphemeralSecret(pub(crate) [u8; 32]);

impl EphemeralSecret {
    pub fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(their_public.0.mul_clamped(self.0))
    }

    pub fn random_from_rng<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        EphemeralSecret(bytes)
    }
}
