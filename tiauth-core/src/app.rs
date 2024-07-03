#![allow(dead_code)]

use crate::crypto::{create_key, load_key, save_private_key, save_public_key, Key, KeyError};
use crate::data::BytePacked;
use crate::Claims;
use crate::{ActionType, Target, TargetList};

pub fn create_private_key_pem() -> String {
    let key = create_key();

    save_private_key(&key)
}

pub fn public_from_private_key_pem(private_key_pem: &str) -> Result<String, KeyError> {
    let key = load_key(private_key_pem)?;

    Ok(save_public_key(&key.to_public_key()).pem())
}

pub struct ProofBaseView<'a> {
    pub application: &'a str,
    pub expires_in: u64,
    pub key: &'a Key,
}

impl<'a> ProofBaseView<'a> {
    pub fn new(application: &'a str, key: &'a Key) -> Self {
        Self {
            application,
            expires_in: 1800,
            key,
        }
    }
}

pub fn create_set_claims_proof(
    proof_base: ProofBaseView,
    user_id: &str,
    claims: &BytePacked<Claims>,
) -> String {
    let action = ActionType::Set;
    let target = Target::Select;
    let target_data = vec![user_id.to_owned()];

    let proof = create_proof(
        proof_base.application,
        proof_base.expires_in,
        action,
        target,
        TargetList::from_vec(target_data),
        claims,
        proof_base.key,
    );

    proof.into_encoded()
}

pub fn create_reset_proof(proof_base: ProofBaseView, user_id: &str) -> String {
    let action = ActionType::Reset;
    let target = Target::Select;
    let target_data = TargetList::from_vec(vec![user_id.to_owned()]);

    let proof: Proof<()> = create_proof(
        proof_base.application,
        proof_base.expires_in,
        action,
        target,
        target_data,
        BytePacked::empty(),
        proof_base.key,
    );

    proof.into_encoded()
}

pub fn create_read_all_proof(proof_base: ProofBaseView) -> String {
    let action = ActionType::Read;
    let target = Target::All;

    let proof: Proof<()> = create_proof(
        proof_base.application,
        proof_base.expires_in,
        action,
        target,
        TargetList::empty(),
        BytePacked::new(&[]),
        proof_base.key,
    );

    proof.into_encoded()
}
