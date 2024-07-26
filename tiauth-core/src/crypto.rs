use aes_gcm_siv::{self as aead, aead::Aead, KeyInit};
use base64::{engine::general_purpose as b64, Engine as _};
use ed25519_compact::{self as ed};
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use thiserror::Error;

#[derive(Clone)]
pub struct Key {
    kp: ed::KeyPair,
}

impl Key {
    pub fn to_public_key(&self) -> PublicKey {
        let pk = self.kp.pk;

        PublicKey { pk }
    }
}

#[derive(Clone)]
pub struct PublicKey {
    pk: ed::PublicKey,
}

pub fn create_key() -> Key {
    let kp = ed::KeyPair::generate();

    Key { kp }
}

pub struct SavedPublicKey(String);

impl SavedPublicKey {
    pub fn validate_pem(public_key_pem: &str) -> Result<Self, KeyError> {
        let key = load_public_key(public_key_pem)?;

        Ok(save_public_key(&key))
    }

    pub fn pem(self) -> String {
        self.0
    }
}

pub fn save_public_key(key: &PublicKey) -> SavedPublicKey {
    SavedPublicKey(key.pk.to_pem())
}

pub fn save_private_key(key: &Key) -> String {
    key.kp.sk.to_pem()
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Failed to parse string as PKCS8-PEM-encoded Ed25519 private key.")]
    Ed25519Private,
    #[error("Failed to parse string as SubjectPublicKeyInfo-PEM-encoded Ed25519 public key.")]
    Ed25519Public,
    #[error("Failed to parse bytes as 256-bit session key.")]
    SessionBytes
}

pub fn load_key(private_key_pem: &str) -> Result<Key, KeyError> {
    // The PEM file contains only the seed, so public key is recomputed and we don't have to validate it
    let sk = ed::SecretKey::from_pem(private_key_pem).map_err(|_| KeyError::Ed25519Private)?;
    let pk = sk.public_key();
    let kp = ed::KeyPair { pk, sk };
    Ok(Key { kp })
}

pub fn load_public_key(public_key_pem: &str) -> Result<PublicKey, KeyError> {
    let pk = ed::PublicKey::from_pem(public_key_pem).map_err(|_| KeyError::Ed25519Public)?;
    Ok(PublicKey { pk })
}

pub fn sign_data(key: &Key, data: &[u8]) -> Vec<u8> {
    let signature = key.kp.sk.sign(data, Some(ed::Noise::generate()));

    signature.to_vec()
}

pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &PublicKey) -> bool {
    match &ed::Signature::from_slice(signature) {
        Ok(sig) => public_key.pk.verify(data, sig).is_ok(),
        Err(_) => false,
    }
}

pub fn create_session_key(rng: &mut StdRng) -> SessionKey {
    let mut key_bytes = [0u8; 32];

    rng.fill_bytes(&mut key_bytes);

    SessionKey {
        key_256: key_bytes.into(),
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct SessionKey {
    key_256: aead::Key<aead::Aes256GcmSiv>,
}

impl SessionKey {
    pub fn into_saved_bytes(self) -> Vec<u8> {
        self.key_256.to_vec()
    }

    pub fn from_saved_bytes(bytes: Vec<u8>) -> Result<Self, KeyError> {
        Ok(SessionKey {
            key_256: aead::Key::<aead::Aes256GcmSiv>::from_exact_iter(bytes).ok_or(KeyError::SessionBytes)?,
        })
    }
}

pub struct SavedSessionKey {
    pub session: String,
}

// pub fn save_session_key(key: &SessionKey) -> SavedSessionKey {
//     let session = b64::URL_SAFE_NO_PAD.encode(key.key_256);

//     SavedSessionKey { session }
// }

// pub fn save_session_key(key: &SessionKey) -> SavedSessionKey {
//     let session = b64::URL_SAFE_NO_PAD.encode(key.key_256);

//     SavedSessionKey { session }
// }

// pub fn load_session_key(session_key_encoded: &str) -> SessionKey {
//     let mut key_256_raw = [0u8; 32];

//     let bytes_written = b64::URL_SAFE_NO_PAD
//         .decode_slice(session_key_encoded, &mut key_256_raw)
//         .unwrap();
//     assert_eq!(bytes_written, 32);
//     SessionKey {
//         key_256: aead::Key::<aead::Aes256GcmSiv>::from_slice(&key_256_raw).to_owned(),
//     }
// }

pub fn session(session_data: &[u8], key: &SessionKey, rng: &mut StdRng) -> Vec<u8> {
    let cipher = aead::Aes256GcmSiv::new(&key.key_256);

    let mut iv_bytes = vec![0u8; 12];
    rng.fill_bytes(&mut iv_bytes);

    let nonce = aead::Nonce::from_slice(&iv_bytes);

    // Tag is appended at the end
    let mut ciphertext = cipher.encrypt(nonce, session_data).unwrap();

    // We put the nonce at the end
    ciphertext.append(&mut iv_bytes);

    ciphertext
}

// HmacSha256 key can be any length up to 64 bytes, but 256 bits of entropy should be plenty.
#[derive(Debug)]
pub struct EphemeralKey {
    bytes: [u8; 32],
}

impl EphemeralKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn compute(base_secret: [u8; 32], now: u64, ref_time: u64) -> Self {
        let passed = now - ref_time;

        let mut rng = ChaCha20Rng::from_seed(base_secret);
        let ten_minute_intervals_passed = passed / 1200;

        rng.set_stream(ten_minute_intervals_passed);
        let mut new_key = [0u8; 32];
        rng.fill_bytes(&mut new_key);

        Self { bytes: new_key }
    }

    pub fn last(
        base_secret: [u8; 32],
        now: u64,
        ref_time: u64,
        amount_valid: u32,
    ) -> Vec<EphemeralKey> {
        (0..(amount_valid as u64))
            .rev()
            .map(|i| Self::compute(base_secret, now - (i * 600), ref_time))
            .collect()
    }
}

type HmacSha256 = Hmac<Sha256>;

pub fn ephemeral(ephemeral_data: &[u8], key: &EphemeralKey) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.bytes).unwrap();

    mac.update(ephemeral_data);

    let code: [u8; 32] = mac.finalize().into_bytes().into();

    code
}

#[derive(Error, Debug)]
#[error("Verification failed.")]
pub struct VerifyFailed;

pub fn verify_ephemeral(
    ephemeral_data: &[u8],
    keys: &[EphemeralKey],
    code: &[u8; 32],
) -> Result<(), VerifyFailed> {
    let mut i = keys.len() - 1;
    loop {
        let key = &keys[i];
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.bytes).unwrap();

        mac.update(ephemeral_data);

        if mac.verify_slice(code).is_ok() {
            return Ok(());
        }

        if i == 0 {
            break;
        }

        i -= 1;
    }

    Err(VerifyFailed)
}

/// The decryption failed. This can be due to tampered data, an invalid key, invalid IV or incorrect tag.
#[derive(Error, Debug)]
#[error("Decryption failed.")]
pub struct DecryptFailed;

pub fn session_decrypt(session: &[u8], key: &SessionKey) -> Result<Vec<u8>, DecryptFailed> {
    let session_len = session.len();
    assert!(session_len >= 28);

    let iv = session.get((session_len - 12)..(session_len)).unwrap();
    let nonce = aead::Nonce::from_slice(iv);
    let ciphertext = session.get(0..(session_len - 12)).unwrap();

    let cipher = aead::Aes256GcmSiv::new(&key.key_256);

    cipher.decrypt(nonce, ciphertext).map_err(|_| DecryptFailed)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn generate_key_length() {
        let key = create_key();

        let raw_private = key.kp.sk.as_slice();

        // Ed25519 private should be 32 bytes, but it also includes public key so 64 bytes
        assert_eq!(raw_private.len(), 64);

        let raw_public = key.kp.pk.as_slice();

        // Ed25519 public should be 32 bytes
        assert_eq!(raw_public.len(), 32);
    }

    #[test]
    fn save_load_key() {
        let key = create_key();

        let saved_key = save_private_key(&key);

        let loaded_key = load_key(&saved_key).unwrap();

        assert_eq!(key.kp, loaded_key.kp);
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
