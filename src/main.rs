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
    println!("\nStarting key exchange!\n");

    let alice_sec = EphemeralSecret::random_from_rng(OsRng);
    println!("alice_sec.to_tab() : {:?}",alice_sec.to_tab());
    let alice_pub = PublicKey::from(&alice_sec);
    println!("alice_pub.as_bytes() : {:?}", alice_pub.as_bytes());

    println!("");

    let bob_sec = EphemeralSecret::random_from_rng(OsRng);
    println!("bob_sec.to_tab() : {:?}",bob_sec.to_tab());
    let bob_pub = PublicKey::from(&bob_sec);
    println!("bob_pub.as_bytes(): {:?}", bob_pub.as_bytes());

    println!("");

    println!("\nScalar :");
    let alice_sec_scalar = alice_sec.get_scalar();    
    println!("alice_sec_scalar.to_bytes() = {:?}",alice_sec_scalar.to_bytes());
    let alice_pub_scalar = alice_pub.get_scalar();
    println!("alice_pub_scalar.to_bytes() = {:?}",alice_pub_scalar.to_bytes());

    println!("");

    let bob_sec_scalar = bob_sec.get_scalar();
    println!("bob_sec_scalar.to_bytes() = {:?}",bob_sec_scalar.to_bytes());
    let bob_pub_scalar = bob_pub.get_scalar();
    println!("bob_pub_scalar.to_bytes() = {:?}",bob_pub_scalar.to_bytes());

    println!("");

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

    println!("\n\n--------------------------------Hashing test-------------------------------------------");
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
    println!("Hash SHA-256 scalar tab (1ère façon): {:?}",scalar_result.to_bytes());
    println!("L'affichage est différent : la conversion en Scalar semble modifier le contenu du tableau (histoire du modulo l, il faut mieux comprendre)\n");

    //seconde facon de convertir le résultat du hash en scalar : 
    let mut bytes2: [u8; 32] = [0; 32];
    bytes2.copy_from_slice(&result);
    println!("bytes2 : {:?}",bytes2);
    let scalar_result2 = Scalar::from_bytes_mod_order(bytes2);
    println!("Hash SHA-256 scalar tab (2nd façon): {:?}",scalar_result2.to_bytes());
    println!("L'affichage est différent : la conversion en Scalar semble modifier le contenu du tableau (histoire du modulo l, il faut mieux comprendre)\n");
    println!("");


    println!("------------------------------------------------------------------------------------------\n\n");
    //fonctionne pas car {:x} pas prit en compte pour le type scalar
    //println!("Hash SHA-256 scalar hex : {:x}",scalar_result.to_bytes());








    println!("\n\n\n\nTest signature :\n");

    //private_singing_key est r
    let private_signing_key = EphemeralSecret::random_from_rng(OsRng);
    println!("(r) private_signing_key : {:?}",private_signing_key.to_tab());
    let private_signing_key_scalar = private_signing_key.get_scalar();
    println!("private_signing_key_scalar = {:?}",private_signing_key_scalar.to_bytes());

    println!("");

    //public_signing_key est R
    let public_signing_key = PublicKey::from(&private_signing_key);
    println!("(R) public_signing_key : {:?}",public_signing_key.as_bytes());
    let public_signing_key_scalar = public_signing_key.get_scalar();
    println!("public_signing_key_scalar = {:?}",public_signing_key_scalar.to_bytes());

    println!("");


    let public_signing_key_tab = *(public_signing_key.as_bytes());
    let alice_pub_tab = *(alice_pub.as_bytes());
    let bob_pub_tab = *(bob_pub.as_bytes());


    //g est le groupe générateur, g_coords est le groupe générateur mit dans un tableau u8; 32
    let g = ED25519_BASEPOINT_POINT;
    let g_coords = g.compress().to_bytes();

    println!("groupe générateur g = {:?}", g);
    println!("g_cooreds : {:?}",g_coords);

    //on créé le scalar g_coords_scalar à partir du tableau g_coords
    let g_coords_scalar = Scalar::from_bytes_mod_order(g_coords);
    println!("g_coords_scalar = {:?}", g_coords_scalar.as_bytes());


    println!("\n\nCalcul de H(R|g|B.pk|M(A.pk)) :\n");

    //calcul de tous les tableaux concaténés

    //conversion en un tableau [u8; 128]
    let mut result: [u8; 128] = [0; 128];
    result[0..32].copy_from_slice(&public_signing_key_scalar.to_bytes());
    result[32..64].copy_from_slice(&g_coords);
    result[64..96].copy_from_slice(&bob_pub_tab);
    result[96..128].copy_from_slice(&alice_pub_tab);

    println!("Concaténation des tableaux : public_signing_key_scalar.to_bytes(), g_coords, bob_pub_tab, alice_pub_tab \n {:?}", result);



    println!("\nHashage du grand tableau avec Sha256 :");
    let mut haser2 = Sha256::new();
    haser2.update(&result);
    let result_hash = haser2.finalize();

    // Affichez la valeur du hachage en format hexadécimal, et en tableau
    println!("\nHash SHA-256 result_hash hex : {:x}", result_hash);
    println!("Hash SHA-256 result_hash tab : {:?}", result_hash);

    let mut hash2_byte_result: [u8; 32] = [0; 32];
    hash2_byte_result.copy_from_slice(&result_hash);
    println!("hash2_byte_result  (c non scalar = H(R|g|B.pk|M) en non scalar): {:?}",hash2_byte_result);
    let c = Scalar::from_bytes_mod_order(hash2_byte_result);

    println!("c (scalar) = H(R|g|B.pk|M))= {:?}",c.as_bytes());


    println!("\n\nCalcul de z :");
    let z = private_signing_key_scalar + c*bob_pub_scalar;
    println!("z = {:?}",z.to_bytes());

    println!("\n\nTransfert de c et de z");

    let big_r_prime_scalar = z*g_coords_scalar - c*bob_pub_scalar;

    println!("--------------------------------------------------------------------------------");
    println!("big_r_prime_scalar(R') doit être égal à public_signing_key_scalar (R) !\n");
    println!("big_r_prime_scalar(R') : {:?}",big_r_prime_scalar.to_bytes());
    println!("");
    println!("public_singing_key (R)  : {:?}",public_signing_key_tab);
    println!("public_signing_key_scalar (R) : {:?}",public_signing_key_scalar.to_bytes());
    println!("--------------------------------------------------------------------------------\n\n");

    //calcul de H(R'|g|b.pk|M)

    let mut gros_tableau: [u8; 128] = [0; 128];

    gros_tableau[0..32].copy_from_slice(&big_r_prime_scalar.to_bytes());
    gros_tableau[32..64].copy_from_slice(&g_coords);
    gros_tableau[64..96].copy_from_slice(&bob_pub_tab);
    gros_tableau[96..128].copy_from_slice(&alice_pub_tab);

    println!("\nConcaténation des tableau pour le second calcul de hash : {:?}", gros_tableau);

    println!("\nCalcul de H(R'|g|b.pk|M");

    let mut hasher3 = Sha256::new();
    hasher3.update(&gros_tableau);
    let result_hash2 = hasher3.finalize();

    // Affichez la valeur du hachage en format hexadécimal, et en tableau
    println!("\nHash SHA-256 result_hash2 hex : {:x}", result_hash2);
    println!("Hash SHA-256 result_hash2 tab : {:?}", result_hash2);
    
    println!("\nVérification de la signature : H(R'|g|B.pk|M) = c ? :");

    println!("--------------------------------------------------------------------");
    println!("hash2_byte_result (c en non scalar) = {:?}",hash2_byte_result);
    println!("c (scalar) = {:?}",c.as_bytes());
    println!("");

    let hash3_byte_result: [u8; 32] = result_hash2.into();
    println!("hash3_byte_result : {:?}",hash3_byte_result);
    let c_prime = Scalar::from_bytes_mod_order(hash3_byte_result);

    println!("c_prime : {:?}",c_prime.as_bytes());
    println!("--------------------------------------------------------------------");
 

    println!("\n\n\n");


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