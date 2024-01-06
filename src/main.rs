use rand_core::OsRng;
use crypto_mob::{EphemeralSecret, PublicKey};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, consts::{B1, B0}, generic_array::GenericArray},
    Aes256Gcm, Key, AesGcm, aes::{Aes256, cipher::typenum::{UInt, UTerm}}
};

type CipherType = AesGcm<Aes256, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>;
type NonceType = GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>;

use sha2::{Sha256,Digest};
use curve25519_dalek::scalar::Scalar;

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
    assert_eq!(alice_shared_sec.as_byte(), bob_shared_sec.as_byte());
    println!("Shared secret is the same : {:?}", shared_key);

    println!("\n\nChiffrement :");
    let cipher = create_cipher(shared_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = encrypt(&cipher, nonce, b"plaintext message");
    println!("Message chiffré : {:?}", ciphertext);
    
    let plaintext = decrypt(&cipher, nonce, ciphertext);
    println!("Message déchiffré : {:?}", plaintext);

    println!("Doit correspondre à : {:?}", b"plaintext message");
    assert_eq!(&plaintext, b"plaintext message");


    println!("\n\n\nScalar :");
    let alice_sec_scalar = alice_sec.get_scalar();    
    println!("alice_sec_scalar = {:?}",alice_sec_scalar.to_bytes());
    let bob_sec_scalar = bob_sec.get_scalar();
    println!("bob_sec_scalar = {:?}",bob_sec_scalar.to_bytes());
    
    let secret_scalar = bob_shared_sec.get_scalar();
    println!("\nsecret_scalar = {:?}",secret_scalar.to_bytes());

    let addition_scalar = secret_scalar + bob_sec_scalar;
    println!("Addition scalar (secret_scalar + bob_sec_scalar) : {:?}",addition_scalar.to_bytes());

    let message: &[u8] = b"This is a test of the tsunami alert system.";
    println!("\n\nMessage : {:?}",message);

    println!("\n\nHashing :");
    // Créez un objet Sha256
    let mut hasher = Sha256::new();
    // Mettez à jour le hachoir avec les données
    hasher.update(&message);
    // Finalisez le hachage et obtenez le résultat
    let result = hasher.finalize();

    
    // Affichez la valeur du hachage en format hexadécimal
    println!("Hash SHA-256 generic-array hex : {:x}", result);
    println!("Hash SHA-256 generic-array tab : {:?}", result);

    let bytes: [u8; 32] = result.into();
    println!("bytes : {:?}",bytes);
    let scalar_result = Scalar::from_bytes_mod_order(bytes);


    println!("Hash SHA-256 scalar tab : {:?}",scalar_result.to_bytes());
    println!("L'affichage est différent, mais c'est normal : c'est la conversion en Scalar qui modifie comment le tableau est affiché");
    //fonctionne pas car {:x} pas prit en compte pour le type scalar
    //println!("Hash SHA-256 scalar hex : {:x}",scalar_result.to_bytes());

    println!("\n\n");
    

    println!("\n\n");
}




pub fn create_cipher(shared_key : &[u8]) -> CipherType{
    let shared_key_slice: &[u8] = &*shared_key;
    let key: [u8; 32] = match shared_key_slice.try_into() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Error: {:?}", error);
            // Gérer l'erreur de manière appropriée
            std::process::exit(1);
        }
    };
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(&key);
    cipher
}

pub fn encrypt(cipher : &CipherType, nonce : NonceType, plaintext : &[u8]) -> Vec<u8>{
    let ciphertext_result = cipher.encrypt(&nonce, plaintext.as_ref());
    let ciphertext = match ciphertext_result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Encryption error: {:?}", error);
            std::process::exit(1);
        }
    };
    ciphertext
}

pub fn decrypt(cipher : &CipherType, nonce : NonceType, ciphertext : Vec<u8>) -> Vec<u8> {
    let plaintext_result = cipher.decrypt(&nonce, ciphertext.as_ref());
    let plaintext = match plaintext_result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Decryption error: {:?}", error);
            std::process::exit(1);
        }
    };
    plaintext
}