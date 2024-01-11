use rand_core::OsRng;
use crypto_mob::{EphemeralSecret, PublicKey};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::traits::Identity;

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

    println!("\n\n\n\nTest signature :\n");

    let private_signing_key = EphemeralSecret::random_from_rng(OsRng);
    let public_signing_key = PublicKey::from(&private_signing_key);
    let public_signing_key_tab = *(public_signing_key.as_bytes());

    let alice_sec = EphemeralSecret::random_from_rng(OsRng);
    let alice_pub = PublicKey::from(&alice_sec);
    let alice_pub_tab = *(alice_pub.as_bytes());

    let bob_sec = EphemeralSecret::random_from_rng(OsRng);
    let bob_pub = PublicKey::from(&bob_sec);
    let bob_pub_tab = *(bob_pub.as_bytes());


    let g = EdwardsPoint::identity();
    let g_coords = g.compress().to_bytes();

    println!("g = {:?}", g);
    println!("g_cooreds : {:?}",g_coords);

    let g_coords_scalar = Scalar::from_bytes_mod_order(g_coords);
    println!("g_coords_scalar = {:?}", g_coords_scalar.as_bytes());

    let private_signing_key_scalar = private_signing_key.get_scalar();
    println!("private_signing_key_scalar = {:?}",private_signing_key_scalar.to_bytes());

    let public_signing_key_scalar = public_signing_key.get_scalar();
    println!("public_signing_key_scalar = {:?}",public_signing_key_scalar.to_bytes());

    println!("\n\nCalcul de H(R|g|B.pk|M(A.pk)) :\n");

    //calcul de tous les tableaux concaténés

    //conversion en un tableau [u8; 128]
    let mut result: [u8; 128] = [0; 128];
    result[0..32].copy_from_slice(&public_signing_key_scalar.to_bytes());
    result[32..64].copy_from_slice(&g_coords);
    result[64..96].copy_from_slice(&bob_pub_tab);
    result[96..128].copy_from_slice(&alice_pub_tab);

    println!("Concaténation des tableaux : {:?}", result);



    
    let mut haser2 = Sha256::new();
    haser2.update(&result);
    let result_hash = haser2.finalize();

    // Affichez la valeur du hachage en format hexadécimal, et en tableau
    println!("\nHash SHA-256 result_hash hex : {:x}", result_hash);
    println!("Hash SHA-256 result_hash tab : {:?}", result_hash);
    
    //c doit etre egal au scalar de la valeur du hash
    let c_bytes: [u8; 32] = result_hash.into();
    println!("c_bytes : {:?}",c_bytes);
    let c_scalar = Scalar::from_bytes_mod_order(c_bytes);

    println!("c_scalar = {:?}",c_scalar.as_bytes());

    println!("\n\nCalcul de z :");
    let bob_pub_tab_scalar = Scalar::from_bytes_mod_order(bob_pub_tab);
    println!("bob_pub_tab_scalar : {:?}",bob_pub_tab_scalar.to_bytes());

    let z = private_signing_key_scalar + c_scalar*bob_pub_tab_scalar;
    println!("z value : {:?}",z.to_bytes());

    println!("\nTransfert de c et de z");

    let r_prime_scalar = z*g_coords_scalar - c_scalar*bob_pub_tab_scalar;

    println!("\nr_prime_scalar(R') doit être égal à public_signing_key_scalar (R) ?\n");
    println!("r_prime : {:?}",r_prime_scalar.to_bytes());
    println!("r_prime : {:?}",r_prime_scalar.as_bytes());
    println!("public_signing_key_scalar : {:?}",public_signing_key_scalar.to_bytes());

    //calcul de H(R'|g|b.pk|M)

    let mut result2: [u8; 128] = [0; 128];

    result2[0..32].copy_from_slice(&r_prime_scalar.to_bytes());
    result2[32..64].copy_from_slice(&g_coords);
    result2[64..96].copy_from_slice(&bob_pub_tab);
    result2[96..128].copy_from_slice(&alice_pub_tab);

    println!("\nConcaténation des tableau pour le second calcul de hash : {:?}", result2);


    let mut hasher3 = Sha256::new();
    hasher3.update(&result2);
    let result_hash2 = hasher3.finalize();

    // Affichez la valeur du hachage en format hexadécimal, et en tableau
    println!("\nHash SHA-256 result_hash2 hex : {:x}", result_hash2);
    println!("Hash SHA-256 result_hash2 tab : {:?}", result_hash2);
    

    println!("Hash SHA-256 result_hash2 tab doit être égal à c : \n");

    println!("c = {:?}",c_bytes);
    println!("c_scalar = {:?}",c_scalar.as_bytes());

    //c doit etre egal au scalar de la valeur du hash
    let hash2_tab: [u8; 32] = result_hash2.into();
    println!("hash2_tab : {:?}",hash2_tab);
    let hash2_scalar = Scalar::from_bytes_mod_order(hash2_tab);

    println!("hash2_scalar : {:?}",hash2_scalar.as_bytes());
    
    println!("\n\n\nTest scalar !");

    // let test1 = bob_pub_tab_scalar.to_bytes();
    let test1: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];
    println!("test1 = {:?}",test1);
    let test1_scalar = Scalar::from_bytes_mod_order(test1);
    println!("test1_scalar = {:?}",test1_scalar);
    println!("test1_scalar.as_bytes() = {:?}",test1_scalar.as_bytes());
    println!("test1_scalar.to_bytes() = {:?}",test1_scalar.to_bytes());

    println!("\n\n\n");
    // let test1 = bob_pub_tab_scalar.to_bytes();
    // let test2: [u8; 32] = [
    //     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    //     0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    //     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    //     0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    // ];
    // println!("test2 = {:?}",test2);
    // let test2_scalar = Scalar::from_bits(test2);
    // println!("test2_scalar = {:?}",test2_scalar);
    // println!("test2_scalar.as_bytes() = {:?}",test2_scalar.as_bytes());
    // println!("test2_scalar.to_bytes() = {:?}",test2_scalar.to_bytes());

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