use rand::{rngs::StdRng, SeedableRng};
use rmp_serde::{decode, encode};
use crate::crypto::{create_key, load_key, save_key};

use super::prove::{Proof, ProofUse};

pub fn create_private_key_pem() -> String {
    let key = create_key();

    save_key(&key).private
}

pub fn public_from_private_key_pem(private_key_pem: &str) -> String {
    let key = load_key(private_key_pem);

    save_key(&key).public
}

/// ProofUse encoded as MessagePack bytes, private key is PEM encoded PKCS#8 Ed448, returns MessagePack proof bytes.
pub fn create_proof(proof_use: &[u8], application: &str, private_key_pem: &str, expires_in: Option<u64>) -> Vec<u8> {
    let proof_use: ProofUse = decode::from_read(proof_use).unwrap();

    let key = load_key(private_key_pem);
    
    let proof = Proof::create(&mut StdRng::from_entropy(), &key, application, expires_in, proof_use);

    encode::to_vec_named(&proof).unwrap()
}