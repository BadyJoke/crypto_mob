use rand_core::OsRng;
use crypto_mob::{EphemeralSecret, PublicKey};

use log::{info, debug};

fn main() {
    pretty_env_logger::init();

    info!("Starting key exchange!");
    let alice_sec = EphemeralSecret::random_from_rng(OsRng);
    let alice_pub = PublicKey::from(&alice_sec);

    debug!("Alice public key : {:?}", alice_pub.as_bytes());

    let bob_sec = EphemeralSecret::random_from_rng(OsRng);
    let bob_pub = PublicKey::from(&bob_sec);

    debug!("Bob public key : {:?}", bob_pub.as_bytes());

    let alice_shared_sec = alice_sec.diffie_hellman(&bob_pub);
    let bob_shared_sec = bob_sec.diffie_hellman(&alice_pub);

    assert_eq!(alice_shared_sec.as_byte(), bob_shared_sec.as_byte());
    info!("Shared secret is the same : {:?}", alice_shared_sec.as_byte());
}
