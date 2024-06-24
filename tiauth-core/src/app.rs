#![allow(dead_code)]

use crate::crypto::{create_key, load_key, save_private_key, save_public_key, Key};
use crate::{ActionType, Target, TargetList};
use crate::{Claims, Proof};
use lazy_borink::Lazy;

pub fn create_private_key_pem() -> String {
    let key = create_key();

    save_private_key(&key)
}

pub fn public_from_private_key_pem(private_key_pem: &str) -> String {
    let key = load_key(private_key_pem);

    save_public_key(&key.to_public_key())
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
    claims: Lazy<Claims>,
) -> String {
    let action = ActionType::Set;
    let target = Target::Select;
    let target_data = Lazy::from_inner(vec![user_id.to_owned()]);

    let proof = Proof::new(
        proof_base.application,
        proof_base.expires_in,
        action,
        target,
        target_data.into(),
        claims,
        proof_base.key,
    );

    proof.into_encoded()
}

pub fn create_reset_proof(proof_base: ProofBaseView, user_id: &str) -> String {
    let action = ActionType::Reset;
    let target = Target::Select;
    let target_data = Lazy::from_inner(vec![user_id.to_owned()]);

    let proof = Proof::new(
        proof_base.application,
        proof_base.expires_in,
        action,
        target,
        target_data.into(),
        Lazy::from_inner(()),
        proof_base.key,
    );

    proof.into_encoded()
}

pub fn create_read_all_proof(proof_base: ProofBaseView) -> String {
    let action = ActionType::Read;
    let target = Target::All;

    let proof = Proof::new(
        proof_base.application,
        proof_base.expires_in,
        action,
        target,
        TargetList::empty(),
        Lazy::from_inner(()),
        proof_base.key,
    );

    proof.into_encoded()
}
