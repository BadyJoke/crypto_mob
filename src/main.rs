// use rand_core::OsRng;
// use crypto_mob::{EphemeralSecret, PublicKey};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key // Or `Aes128Gcm`
};

fn main() {
    
    // Note that you can get byte array from slice using the `TryInto` trait:
    let key: &[u8] = &[42; 32];
    let key: [u8; 32] = match key.try_into() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Error: {:?}", error);
            // Gérer l'erreur de manière appropriée
            std::process::exit(1);

        }
    };

    // Alternatively, the key can be transformed directly from a byte slice
    // (panicks on length mismatch):
    let key = Key::<Aes256Gcm>::from_slice(&key);
    
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext_result = cipher.encrypt(&nonce, b"plaintext message".as_ref());
    let ciphertext = match ciphertext_result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Encryption error: {:?}", error);
            std::process::exit(1);
        }
    };

    println!("Message encrypté : {:?}", ciphertext);
    
    let plaintext_result = cipher.decrypt(&nonce, ciphertext.as_ref());
    let plaintext = match plaintext_result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Decryption error: {:?}", error);
            std::process::exit(1);
        }
    };

    println!("Message décrypté : {:?}", plaintext);

    println!("Doit correspondre à : {:?}", b"plaintext message");

    assert_eq!(&plaintext, b"plaintext message");

}

    // println!("Starting key exchange!");
    // let alice_sec = EphemeralSecret::random_from_rng(OsRng);
    // let alice_pub = PublicKey::from(&alice_sec);

    // println!("Alice public key : {:?}", alice_pub.as_bytes());

    // let bob_sec = EphemeralSecret::random_from_rng(OsRng);
    // let bob_pub = PublicKey::from(&bob_sec);

    // println!("Bob public key : {:?}", bob_pub.as_bytes());

    // let alice_shared_sec = alice_sec.diffie_hellman(&bob_pub);
    // let bob_shared_sec = bob_sec.diffie_hellman(&alice_pub);

    // let shared_key = alice_shared_sec.as_byte();

    // assert_eq!(alice_shared_sec.as_byte(), bob_shared_sec.as_byte());
    // println!("Shared secret is the same : {:?}", shared_key);