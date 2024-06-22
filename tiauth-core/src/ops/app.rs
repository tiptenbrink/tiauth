use rand::{rngs::StdRng, SeedableRng};
use rmp_serde::decode;
use lazy_borink::Lazy;
use crate::crypto::{create_key, load_key, save_key};

use super::prove::{Proof, ProofScope};

pub fn create_private_key_pem() -> String {
    let key = create_key();

    save_key(&key).private
}

pub fn public_from_private_key_pem(private_key_pem: &str) -> String {
    let key = load_key(private_key_pem);

    save_key(&key).public
}

// fn create_proof_use() -> Vec<u8> {

// }

pub fn create_proof_struct(proof_use: Lazy<ProofScope>, application: &str, private_key_pem: &str, expires_in: Option<u64>) -> Proof {
    let key = load_key(private_key_pem);
    
    Proof::create(&mut StdRng::from_entropy(), &key, application, expires_in, proof_use)
}

// /// ProofScope encoded as MessagePack bytes, private key is PEM encoded PKCS#8 Ed448, returns MessagePack proof bytes.
// pub fn create_proof_json(proof_use: &[u8], application: &str, private_key_pem: &str, expires_in: Option<u64>) -> String {
//     let proof = create_proof_struct(proof_use, application, private_key_pem, expires_in);

//     serde_json::to_string(&Lazy::from_inner(proof)).unwrap()
// }

// pub fn create_proof(proof_use: &[u8], application: &str, private_key_pem: &str, expires_in: Option<u64>) -> Vec<u8> {
//     let proof = create_proof_struct(proof_use, application, private_key_pem, expires_in);

//     rmp_serde::encode::to_vec_named(&Lazy::from_inner(proof)).unwrap()
// }