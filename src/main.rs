
use rand_core::OsRng;
use crypto_mob::{EphemeralSecret, PublicKey};

fn main(){

    //////// Partie allocation des clés
    let alice_x = EphemeralSecret::random_from_rng(OsRng);
    let alice_grandx = PublicKey::from(&alice_x);
    let alice_sk = EphemeralSecret::random_from_rng(OsRng);
    let alice_pk = PublicKey::from(&alice_sk);

    println!("X : {:?}", alice_grandx.as_bytes());
    println!("alice.pk: {:?}", alice_pk.as_bytes());

    let bob_y = EphemeralSecret::random_from_rng(OsRng);
    let bob_grandy = PublicKey::from(&bob_y);
    let bob_sk = EphemeralSecret::random_from_rng(OsRng);
    let bob_pk = PublicKey::from(&bob_sk);

    println!("Y: {:?}", bob_grandy.as_bytes());
    println!("bob.pk: {:?}", bob_pk.as_bytes());

    let ope_a_sk = EphemeralSecret::random_from_rng(OsRng);
    let ope_a_pk = PublicKey::from(&ope_a_sk);
    let ope_b_sk = EphemeralSecret::random_from_rng(OsRng);
    let ope_b_pk = PublicKey::from(&ope_b_sk);

    println!("Oa.pk: {:?}", ope_a_pk.as_bytes());
    println!("Ob.pk: {:?}", ope_b_pk.as_bytes());
    println!("\n\n");

    //////// Fin de la partie allocation des clés
    
    //////// Partie Diffie Hellman

    let alice_shared_sec = alice_x.diffie_hellman(&bob_grandy);
    let bob_shared_sec = bob_y.diffie_hellman(&alice_grandx);

    let shared_key: &[u8; 32] = alice_shared_sec.as_byte();

    assert_eq!(alice_shared_sec.as_byte(), bob_shared_sec.as_byte());
    println!("Shared secret is the same : {:?}", shared_key);
    println!("\n\n");

    //////// Fin de la partie Diffie Hellman
    

    //////// Partie création de la signature

    //////// Fin de la partie création de la signature



    // //////// Partie chiffrage de message avec la clé partagée

    // let cipher = create_cipher(shared_key);
    // let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    // let ciphertext = encrypt(&cipher, nonce, b"plaintext message");

    // println!("Message chiffré : {:?}", ciphertext);
    
    // let plaintext = decrypt(&cipher, nonce, ciphertext);

    // println!("Message déchiffré : {:?}", plaintext);

    // println!("Doit correspondre à : {:?}", b"plaintext message");

    // assert_eq!(&plaintext, b"plaintext message");

    // //////// Fin de la partie chiffrage de message avec la clé partagée


}
