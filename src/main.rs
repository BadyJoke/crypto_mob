use rand_core::OsRng;
use crypto_mob::{EphemeralSecret, PublicKey};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key // Or `Aes128Gcm`
};

use crypto_mob::hash;

//use ed25519_dalek::{Signature, SigningKey, Signer, Verifier, VerifyingKey}



fn main() {


    println!("Starting key exchange!");
    let alice_sec = EphemeralSecret::random_from_rng(OsRng);
    let alice_pub = PublicKey::from(&alice_sec);

    println!("Alice public key : {:?}", alice_pub.as_bytes());

    let bob_sec = EphemeralSecret::random_from_rng(OsRng);
    let bob_pub = PublicKey::from(&bob_sec);

    println!("Bob public key : {:?}", bob_pub.as_bytes());

    let alice_shared_sec = alice_sec.diffie_hellman(&bob_pub);
    let bob_shared_sec = bob_sec.diffie_hellman(&alice_pub);

    let shared_key: &[u8; 32] = alice_shared_sec.as_byte();

    let shared_key_slice: &[u8] = &*shared_key;

    assert_eq!(alice_shared_sec.as_byte(), bob_shared_sec.as_byte());
    println!("Shared secret is the same : {:?}", shared_key);

    println!("\n\n");

    
    // Note that you can get byte array from slice using the `TryInto` trait:
    //let key: &[u8] = &[42; 32];
    let key: [u8; 32] = match shared_key_slice.try_into() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Error: {:?}", error);
            // Gérer l'erreur de manière appropriée
            std::process::exit(1);

        }
    };

    println!("key : {:?}",key);

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

    
    println!("\n\n\nScalar :");
    let alice_sec_scalar = alice_sec.get_scalar();    
    println!("alice_sec_scalar = {:?}",alice_sec_scalar.to_bytes());
    let bob_sec_scalar =bob_sec.get_scalar();
    println!("bob_sec_scalar = {:?}",bob_sec_scalar.to_bytes());

    let alice_pub_scalar = alice_pub.get_scalar();
    println!("\n\nalice_pub_scalar = {:?}",alice_pub_scalar.to_bytes());
    let bob_pub_scalar = bob_pub.get_scalar();
    println!("bob_pub_scalar = {:?}",bob_pub_scalar.to_bytes());

    let secret_scalar = alice_shared_sec.get_scalar();
    println!("\n\nsecret_shared_scalar = {:?}",secret_scalar.to_bytes());


    let all_data: &[u8] = b"To really appreciate architecture, you may even need to commit a murder."
    let result = hash(all_data);
    println!("Hash de dall_data : {:x}",result.to_bytes());



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



    /*
    println!("\n\n\n\n");
    println!("Signature :");

    
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    println!("signing key {:?}",signing_key.as_bytes());

    let message: &[u8] = b"This is a test of the tsunami alert system.";

    println!("Message : {:?}",message);

    let signature: Signature = signing_key.sign(message);

    println!("Signature : {:?}",signature.to_bytes());

    let verifying_key: VerifyingKey = signing_key.verifying_key();

    println!("Verifying key : {:?}",verifying_key);

    let verification = signing_key.verify(message, &signature).is_ok();

    println!("Verification avec signing_key: {verification}");


    let verification2 = verifying_key.verify(message, &signature).is_ok();

    println!("Verification avec verifyin_key : {verification2}");

    
*/