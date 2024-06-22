#![allow(dead_code, unused_imports)]

use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};
use rmp_serde::decode;
use lazy_borink::Lazy;
use tiauth_core::api::prove::{ActionType, Target};
use tiauth_core::crypto::{create_key, load_key, save_key, Key};
use base64::{engine::general_purpose as b64, Engine as _};
use tiauth_core::api::{Claims, Proof};

pub fn create_private_key_pem() -> String {
    let key = create_key();

    save_key(&key).private
}

pub fn public_from_private_key_pem(private_key_pem: &str) -> String {
    let key = load_key(private_key_pem);

    save_key(&key).public
}


pub struct ProofBase {
    pub application: String,
    pub expires_in: u64,
    pub key: Key
}

impl ProofBase {
    pub fn new(application: &str, private_key_pem: &str) -> Self {
        let key = load_key(private_key_pem);
        Self {
            application: application.to_owned(),
            expires_in: 1800,
            key
        }
    }
}

pub fn create_set_claims_proof(proof_base: ProofBase, user_id: &str, claims: Lazy<Claims>) -> String {
    let action = ActionType::Set;
    let target = Target::Select;
    let target_data = Lazy::from_inner(vec![user_id.to_owned()]);
    
    let proof = Proof::new(&proof_base.application, proof_base.expires_in, action, target, target_data.into(), claims, &proof_base.key);

    proof.into_encoded()
}

pub fn create_reset_proof(proof_base: ProofBase, user_id: &str) -> String {
    let action = ActionType::Reset;
    let target = Target::Select;
    let target_data = Lazy::from_inner(vec![user_id.to_owned()]);
    
    let proof = Proof::new(&proof_base.application, proof_base.expires_in, action, target, target_data.into(), Lazy::from_inner(()), &proof_base.key);

    proof.into_encoded()
}