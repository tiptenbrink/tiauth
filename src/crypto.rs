use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::{Signer, Verifier};
use base64::{engine::general_purpose as b64, Engine as _};
use openssl::symm::{encrypt_aead, Cipher, decrypt_aead};
use rand::rngs::StdRng;
use rand::RngCore;

struct CryptoError {

}

pub struct Key {
    openssl_ed448: PKey<Private>
}

pub struct SavedKeypair {
    // PEM encoded SubjectPublicKeyInfo
    pub public: String,
    
    // PEM encoded PKCS#8
    pub private: String
}

pub struct PublicKey {
    key: String
}


pub fn create_key() -> Key {
    let openssl_ed448 = PKey::generate_ed448().unwrap();

    Key {
        openssl_ed448
    }
}

pub fn save_key(key: &Key) -> SavedKeypair {
    // PEM encoded PKCS#8
    let private_pem = key.openssl_ed448.private_key_to_pem_pkcs8().unwrap();
    let private = String::from_utf8(private_pem).unwrap();
    // PEM encoded SubjectPublicKeyInfo
    let public_pem = key.openssl_ed448.public_key_to_pem().unwrap();
    let public = String::from_utf8(public_pem).unwrap();

    SavedKeypair {
        public,
        private
    }
}

pub fn load_key(private_key_pem: &str) -> Key {
    let openssl_ed448 = PKey::private_key_from_pem(private_key_pem.as_bytes()).unwrap();

    Key {
        openssl_ed448
    }
}

pub fn signature_encoded(key: &Key, data: &[u8]) -> String {
    // Only accept Ed448 keys
    assert_eq!(Id::ED448, key.openssl_ed448.id());

    let mut signer = Signer::new_without_digest(&key.openssl_ed448).unwrap();
    signer.update(data).unwrap();

    let signature = signer.sign_to_vec().unwrap();

    b64::URL_SAFE_NO_PAD.encode(signature)
}

pub fn create_session_key(rng: &mut StdRng) -> SessionKey {
    let mut key_bytes = [0u8; 32];

    rng.fill_bytes(&mut key_bytes);

    SessionKey {
        key_256_raw: key_bytes
    }
}

pub struct SessionKey {
    key_256_raw: [u8; 32]
}


pub fn session(session_data: &[u8], key: &SessionKey, rng: &mut StdRng) {
    let cipher = Cipher::aes_256_gcm();

    let mut iv_bytes = vec![0u8; 12];
    rng.fill_bytes(&mut iv_bytes);

    let mut tag = vec![0u8; 16];

    let mut ciphertext = encrypt_aead(cipher, &key.key_256_raw, Some(&iv_bytes), b"", session_data, &mut tag).unwrap();

    // We add the authentication tag to the end
    ciphertext.append(&mut tag);
    ciphertext.append(&mut iv_bytes);
}

pub fn session_decrypt(session: &[u8], key: &SessionKey) -> Vec<u8> {
    let session_len = session.len();
    assert!(session_len >= 28);

    let iv = session.get((session_len-16)..(session_len)).unwrap();
    let tag = session.get((session_len-28)..(session_len-16)).unwrap();
    let ciphertext = session.get(0..(session_len-28)).unwrap();

    let cipher = Cipher::aes_256_gcm();
    
    decrypt_aead(cipher, &key.key_256_raw, Some(iv), b"", ciphertext, tag).unwrap()
}