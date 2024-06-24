use base64::{engine::general_purpose as b64, Engine as _};
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use rand::rngs::StdRng;
use rand::RngCore;

const ALGORITHM: Id = Id::ED25519;

struct CryptoError {}

pub struct Key {
    openssl_ed448: PKey<Private>,
}

impl Key {
    pub fn to_public_key(&self) -> PublicKey {
        let key = self.openssl_ed448.raw_public_key().unwrap();
        let openssl_ed448 = PKey::public_key_from_raw_bytes(&key, ALGORITHM).unwrap();

        PublicKey { openssl_ed448 }
    }
}

pub struct SavedKeypair {
    // PEM encoded SubjectPublicKeyInfo
    pub public: String,

    // PEM encoded PKCS#8
    pub private: String,
}

#[derive(Clone)]
pub struct PublicKey {
    openssl_ed448: PKey<Public>,
}

pub fn create_key() -> Key {
    //let openssl_ed448 = PKey::generate_ed448().unwrap();
    let openssl_ed448 = PKey::generate_ed25519().unwrap();
    Key { openssl_ed448 }
}

pub fn save_key(key: &Key) -> SavedKeypair {
    // PEM encoded PKCS#8
    let private_pem = key.openssl_ed448.private_key_to_pem_pkcs8().unwrap();
    let private = String::from_utf8(private_pem).unwrap();
    // PEM encoded SubjectPublicKeyInfo
    let public_pem = key.openssl_ed448.public_key_to_pem().unwrap();
    let public = String::from_utf8(public_pem).unwrap();

    SavedKeypair { public, private }
}

pub fn load_key(private_key_pem: &str) -> Key {
    let openssl_ed448 = PKey::private_key_from_pem(private_key_pem.as_bytes()).unwrap();

    Key { openssl_ed448 }
}

pub fn load_public_key(public_key_pem: &str) -> PublicKey {
    let openssl_ed448 = PKey::public_key_from_pem(public_key_pem.as_bytes()).unwrap();

    PublicKey { openssl_ed448 }
}

pub fn sign_data(key: &Key, data: &[u8]) -> Vec<u8> {
    // Only accept Ed448 keys
    assert!(key.openssl_ed448.id() == Id::ED25519 || key.openssl_ed448.id() == Id::ED448);
    //assert_eq!(Id::ED448, key.openssl_ed448.id());

    let mut signer = Signer::new_without_digest(&key.openssl_ed448).unwrap();

    signer.sign_oneshot_to_vec(data).unwrap()
}

pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &PublicKey) -> bool {
    let mut verifier = Verifier::new_without_digest(&public_key.openssl_ed448).unwrap();

    verifier.verify_oneshot(signature, data).unwrap()
}

pub fn create_session_key(rng: &mut StdRng) -> SessionKey {
    let mut key_bytes = [0u8; 32];

    rng.fill_bytes(&mut key_bytes);

    SessionKey {
        key_256_raw: key_bytes,
    }
}

pub struct SessionKey {
    key_256_raw: [u8; 32],
}

pub struct SavedSessionKey {
    pub session: String,
}

pub fn save_session_key(key: &SessionKey) -> SavedSessionKey {
    let session = b64::URL_SAFE_NO_PAD.encode(key.key_256_raw);

    SavedSessionKey { session }
}

pub fn load_session_key(session_key_encoded: &str) -> SessionKey {
    let mut key_256_raw = [0u8; 32];

    let bytes_written = b64::URL_SAFE_NO_PAD
        .decode_slice(session_key_encoded, &mut key_256_raw)
        .unwrap();
    assert_eq!(bytes_written, 32);

    SessionKey { key_256_raw }
}

pub fn session(session_data: &[u8], key: &SessionKey, rng: &mut StdRng) -> Vec<u8> {
    let cipher = Cipher::aes_256_gcm();

    let mut iv_bytes = vec![0u8; 12];
    rng.fill_bytes(&mut iv_bytes);

    let mut tag = vec![0u8; 16];

    let mut ciphertext = encrypt_aead(
        cipher,
        &key.key_256_raw,
        Some(&iv_bytes),
        b"",
        session_data,
        &mut tag,
    )
    .unwrap();

    // We add the authentication tag to the end
    ciphertext.append(&mut tag);
    ciphertext.append(&mut iv_bytes);

    ciphertext
}

/// The decryption failed. This can be due to tampered data, an invalid key, invalid IV or incorrect tag.
#[derive(Debug)]
pub struct DecryptFailed {}

pub fn session_decrypt(session: &[u8], key: &SessionKey) -> Result<Vec<u8>, DecryptFailed> {
    let session_len = session.len();
    assert!(session_len >= 28);

    let iv = session.get((session_len - 12)..(session_len)).unwrap();
    let tag = session.get((session_len - 28)..(session_len - 12)).unwrap();
    let ciphertext = session.get(0..(session_len - 28)).unwrap();

    let cipher = Cipher::aes_256_gcm();

    match decrypt_aead(cipher, &key.key_256_raw, Some(iv), b"", ciphertext, tag) {
        Ok(decrypted) => Ok(decrypted),
        // If something with the data is wrong, no errors will be reported
        Err(e) => {
            if e.errors().is_empty() {
                Err(DecryptFailed {})
            } else {
                panic!("Internal OpenSSL error!")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn generate_key_length() {
        let key = create_key();

        let raw_private = key.openssl_ed448.raw_private_key().unwrap();

        // Ed448 private should be 57 bytes
        assert_eq!(raw_private.len(), 57);

        let raw_public = key.openssl_ed448.raw_public_key().unwrap();

        // Ed448 public should be 57 bytes
        assert_eq!(raw_public.len(), 57);
    }

    #[test]
    fn save_load_key() {
        let key = create_key();

        let saved_key = save_key(&key);

        let loaded_key = load_key(&saved_key.private);

        assert_eq!(
            key.openssl_ed448.raw_public_key().unwrap(),
            loaded_key.openssl_ed448.raw_public_key().unwrap()
        );
        assert_eq!(
            key.openssl_ed448.raw_private_key().unwrap(),
            loaded_key.openssl_ed448.raw_private_key().unwrap()
        );
    }

    #[test]
    fn sign_verify_data() {
        let key = create_key();

        let data = b"some_data";

        let signature = sign_data(&key, data);

        assert!(verify_signature(
            data,
            signature.as_slice(),
            &key.to_public_key()
        ))
    }

    #[test]
    fn sign_invalid_data() {
        let key = create_key();

        let data = b"some_data";

        let signature = sign_data(&key, data);

        assert!(!verify_signature(
            b"other_data",
            signature.as_slice(),
            &key.to_public_key()
        ))
    }

    #[test]
    fn sign_invalid_sig() {
        let key = create_key();

        let data = b"some_data";

        assert!(!verify_signature(data, b"bad_sig", &key.to_public_key()))
    }

    #[test]
    fn sign_invalid_pub_key() {
        let key = create_key();

        let data = b"some_data";

        let signature = sign_data(&key, data);

        let other_key = create_key().to_public_key();

        assert!(!verify_signature(data, &signature, &other_key))
    }

    #[test]
    fn encrypt_decrypt() {
        let mut seed = [0u8; 32];
        OsRng.fill(&mut seed);
        let mut rng = StdRng::from_seed(seed);

        let key = create_session_key(&mut rng);

        let data = "this_is_some_amount_of_data_that_I_encrypt";

        let encrypted = session(data.as_bytes(), &key, &mut rng);

        let data_decrypt = session_decrypt(&encrypted, &key).unwrap();

        assert_eq!(data.as_bytes(), data_decrypt);
    }

    #[test]
    fn encrypt_decrypt_different() {
        let mut seed = [0u8; 32];
        OsRng.fill(&mut seed);
        let mut rng = StdRng::from_seed(seed);

        let key = create_session_key(&mut rng);

        let data = "this_is_some_amount_of_data_that_I_encrypt";

        let encrypted = session(data.as_bytes(), &key, &mut rng);

        let mut encrypted_tampered = encrypted.clone();
        let mut encrypted_invalid_iv = encrypted.clone();
        let mut encrypted_bad_tag = encrypted.clone();

        if encrypted_tampered[0] != 3 {
            encrypted_tampered[0] = 3
        } else {
            encrypted_tampered[0] = 2;
        }

        let encrypted_len = encrypted.len();

        if encrypted_invalid_iv[encrypted_len - 1] != 3 {
            encrypted_invalid_iv[encrypted_len - 1] = 3
        } else {
            encrypted_invalid_iv[encrypted_len - 1] = 2;
        }

        if encrypted_bad_tag[encrypted_len - 20] != 3 {
            encrypted_bad_tag[encrypted_len - 20] = 3
        } else {
            encrypted_bad_tag[encrypted_len - 20] = 2;
        }

        let tampered_decrypt = session_decrypt(&encrypted_tampered, &key);
        let invalid_iv_decrypt = session_decrypt(&encrypted_invalid_iv, &key);
        let bad_tag_decrypt = session_decrypt(&encrypted_bad_tag, &key);

        assert!(tampered_decrypt.is_err());
        assert!(invalid_iv_decrypt.is_err());
        assert!(bad_tag_decrypt.is_err());
    }
}
