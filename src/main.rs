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

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

fn main() {
    println!("\nCréation des clés publiques et privés de Alice et Bob\n");

    let (alice_sec, alice_pub) = generate_ephemeral_keypair();
    println!("alice_sec.to_tab() : {:?}",alice_sec.to_tab());
    println!("alice_pub.as_bytes() : {:?}\n", alice_pub.as_bytes());

    println!("");

    let (bob_sec, bob_pub) = generate_ephemeral_keypair();
    println!("bob_sec.to_tab() : {:?}",bob_sec.to_tab());
    println!("bob_pub.as_bytes(): {:?}\n", bob_pub.as_bytes());

    println!("");

    println!("\nScalar :");
    let alice_sec_scalar = alice_sec.get_scalar();    
    println!("alice_sec_scalar.to_bytes() = {:?}",alice_sec_scalar.to_bytes());
    let alice_pub_scalar = alice_pub.get_scalar(); //X
    println!("alice_pub_scalar.to_bytes() = {:?}",alice_pub_scalar.to_bytes());

    println!("");

    let bob_sec_scalar = bob_sec.get_scalar();
    println!("bob_sec_scalar.to_bytes() = {:?}",bob_sec_scalar.to_bytes());
    let bob_pub_scalar = bob_pub.get_scalar(); //Y
    println!("bob_pub_scalar.to_bytes() = {:?}",bob_pub_scalar.to_bytes());

    println!("\nEchange de clé : \n");

    let alice_shared_sec = alice_sec.diffie_hellman(&bob_pub);
    let bob_shared_sec = bob_sec.diffie_hellman(&alice_pub);
    let shared_key: &[u8; 32] = alice_shared_sec.as_byte();
    assert_eq!(alice_shared_sec.as_byte(), bob_shared_sec.as_byte());
    println!("shared_key : {:?}", shared_key);

    let secret_scalar = bob_shared_sec.get_scalar();
    println!("\nsecret_scalar.to_bytes() = {:?}",secret_scalar.to_bytes());

    println!("\n\nChiffrement :");
    let cipher = create_cipher(shared_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = encrypt(&cipher, nonce, b"plaintext message");
    println!("Message chiffré : {:?}", ciphertext);
    
    let plaintext = decrypt(&cipher, nonce, ciphertext);
    println!("Message déchiffré : {:?}", plaintext);

    println!("Doit correspondre à : {:?}", b"plaintext message");
    assert_eq!(&plaintext, b"plaintext message");


    //fonctionne pas car {:x} pas prit en compte pour le type scalar
    //println!("Hash SHA-256 scalar hex : {:x}",scalar_result.to_bytes());


    println!("\n\n--------------------------------Signature-------------------------------------------\n\n");


    let (r_ephem, grand_r_publickey) = generate_ephemeral_keypair();
    let r_edward = r_ephem.to_edwards_point();
    let grand_r_edward = grand_r_publickey.to_edwards_point();
    println!("R = {:?}", grand_r_edward);

    let g = ED25519_BASEPOINT_POINT;
    let g_tab = g.compress().to_bytes();

    let (bob_sk_ephem, bob_pk_publickey) = generate_ephemeral_keypair();
    let bob_sk_edward = bob_sk_ephem.to_edwards_point();
    let bob_pk_edward = bob_pk_publickey.to_edwards_point();

    let alice_pub_tab = *(alice_pub.as_bytes());
    let bob_pub_tab = *(bob_pub.as_bytes());
    let bob_pk_tab = *(bob_pk_publickey.as_bytes());
    let grand_r_tab = *(grand_r_publickey.as_bytes());

/*/
    let mut result_1: [u8; 160] = [0; 160];
    result_1[0..32].copy_from_slice(&grand_r_tab);
    result_1[32..64].copy_from_slice(&g_tab);
    result_1[64..96].copy_from_slice(&bob_pk_tab);
    result_1[96..128].copy_from_slice(&alice_pub_tab);
    result_1[128..160].copy_from_slice(&bob_pub_tab);


    let mut hasher = Sha256::new();
    hasher.update(&result_1);
    let result_hash = hasher.finalize();
    let mut hash_byte_result: [u8; 32] = [0; 32];
    hash_byte_result.copy_from_slice(&result_hash);
    let c = Scalar::from_bytes_mod_order(hash_byte_result);
    println!("c result hash : {:?}",c);
    */


//---------------------------------------AJOUT DE LA FONCTION, RESULTAT LE MEME QUE SANS LA FONCTION--------------------------------------------------
    let mut message = Vec::new();
    message.extend_from_slice(&alice_pub_tab);
    message.extend_from_slice(&bob_pub_tab);

    let c_scalar = hash_tab_get_scalar(&grand_r_tab,&g_tab,&bob_pk_tab,&message);
    println!("c bis result hash : {:?}",c_scalar.as_bytes());
//---------------------------------------AJOUT DE LA FONCTION, RESULTAT LE MEME QUE SANS LA FONCTION--------------------------------------------------


    let z_edward = r_edward + c_scalar*bob_sk_edward;
    let z_montgom = z_edward.to_montgomery();
    let z_bytes = z_montgom.to_bytes();
    let z_scalar = Scalar::from_bytes_mod_order(z_bytes);

    let grand_r_prime_edward = z_scalar*g - c_scalar*bob_pk_edward;
    println!("R' : {:?}", grand_r_prime_edward);

    let grand_r_prime_montgom = grand_r_prime_edward.to_montgomery();
    let grand_r_prime_tab = grand_r_prime_montgom.to_bytes();

    /*
    let mut result_2: [u8; 160] = [0; 160];
    result_2[0..32].copy_from_slice(&grand_r_prime_tab);
    result_2[32..64].copy_from_slice(&g_tab);
    result_2[64..96].copy_from_slice(&bob_pk_tab);
    result_2[96..128].copy_from_slice(&alice_pub_tab);
    result_2[128..160].copy_from_slice(&bob_pub_tab);

    let mut hasher2 = Sha256::new();
    hasher2.update(&result_2);
    let result_hash2 = hasher2.finalize();
    let mut hash2_byte_result: [u8; 32] = [0; 32];
    hash2_byte_result.copy_from_slice(&result_hash2);
    let c_prime = Scalar::from_bytes_mod_order(hash2_byte_result);
    */

    let c_prime_scalar = hash_tab_get_scalar(&grand_r_prime_tab, &g_tab,&bob_pk_tab,&message);
    
    println!("c : {:?}", c_scalar.as_bytes());
    println!("c' : {:?}", c_prime_scalar.as_bytes());

    println!("\n\n");

}

fn hash_tab_get_scalar(
    grand_r_prime_tab: &[u8; 32],
    g_rab: &[u8; 32],
    bob_pk_tab: &[u8; 32],
    message: &[u8],
) -> Scalar{
    // Créer un vecteur pour contenir le résultat
    let mut result: Vec<u8> = Vec::new();

    // Concaténer les tableaux
    result.extend_from_slice(grand_r_prime_tab);
    result.extend_from_slice(g_rab);
    result.extend_from_slice(bob_pk_tab);
    result.extend_from_slice(message);

    let mut hasher = Sha256::new();
    hasher.update(&result);
    let result_hash = hasher.finalize();
    let mut result_hash_tab: [u8; 32] = [0; 32];
    result_hash_tab.copy_from_slice(&result_hash);
    let c = Scalar::from_bytes_mod_order(result_hash_tab);
    c
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

fn generate_ephemeral_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let public: PublicKey = PublicKey::from(&secret);
    (secret, public)
}