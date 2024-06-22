#![allow(dead_code)]

use lazy_borink::Lazy;
use tiauth_core::api::prove::{ActionType, Target};
use tiauth_core::api::{Claims, Proof};
use tiauth_core::crypto::{create_key, load_key, save_key, Key};

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
    pub key: Key,
}

impl ProofBase {
    pub fn new(application: &str, private_key_pem: &str) -> Self {
        let key = load_key(private_key_pem);
        Self {
            application: application.to_owned(),
            expires_in: 1800,
            key,
        }
    }
}

pub fn create_set_claims_proof(
    proof_base: ProofBase,
    user_id: &str,
    claims: Lazy<Claims>,
) -> String {
    let action = ActionType::Set;
    let target = Target::Select;
    let target_data = Lazy::from_inner(vec![user_id.to_owned()]);

    let proof = Proof::new(
        &proof_base.application,
        proof_base.expires_in,
        action,
        target,
        target_data.into(),
        claims,
        &proof_base.key,
    );

    proof.into_encoded()
}

pub fn create_reset_proof(proof_base: ProofBase, user_id: &str) -> String {
    let action = ActionType::Reset;
    let target = Target::Select;
    let target_data = Lazy::from_inner(vec![user_id.to_owned()]);

    let proof = Proof::new(
        &proof_base.application,
        proof_base.expires_in,
        action,
        target,
        target_data.into(),
        Lazy::from_inner(()),
        &proof_base.key,
    );

    proof.into_encoded()
}
