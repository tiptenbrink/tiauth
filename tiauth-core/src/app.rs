#![allow(dead_code)]

use crate::crypto::{create_key, load_key, save_private_key, save_public_key, Key, KeyError};
use crate::data::{empty_packed, BytePacked};
use crate::encoded::Encoded;
use crate::proof::{Ephemeral, ProofAction};
use crate::{ActionType, Target, TargetList};
use crate::{Claims, Proof};

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
    pub now: u64,
    pub nonce: &'a BytePacked<Ephemeral<()>>,
    pub key: &'a Key,
}

impl<'a> ProofBaseView<'a> {
    pub fn new(
        application: &'a str,
        key: &'a Key,
        now: u64,
        nonce: &'a BytePacked<Ephemeral<()>>,
    ) -> Self {
        Self {
            application,
            expires_in: 1800,
            key,
            now,
            nonce,
        }
    }
}

pub fn create_set_claims_proof(
    proof_base: ProofBaseView,
    user_id: &str,
    claims: &BytePacked<Claims>,
) -> Encoded<Proof<Claims>> {
    let action = ActionType::SetClaims;
    let target = Target::Select;
    let target_data = TargetList::user(user_id);
    let action = ProofAction::new(action, target, target_data);

    let proof = Proof::create(
        proof_base.key,
        proof_base.expires_in + proof_base.now,
        action,
        proof_base.nonce,
        claims,
    );

    Encoded::from_encodable(proof)
}

// pub fn create_reset_proof(proof_base: ProofBaseView, user_id: &str) -> Encoded<Proof<()>> {
//     let action = ActionType::Reset;
//     let target = Target::Select;
//     let target_data = TargetList::from_vec(vec![user_id.to_owned()]);

//     let proof: Proof<()> = Proof::create(
//         proof_base.application,
//         proof_base.expires_in,
//         action,
//         target,
//         target_data,
//         BytePacked::empty(),
//         proof_base.key,
//     );

//     Encoded::from_encodable(proof)
// }

pub fn create_read_all_proof(proof_base: ProofBaseView) -> Encoded<Proof<()>> {
    let action = ActionType::ReadUsers;
    let target = Target::All;
    let target_data = TargetList::empty();
    let action = ProofAction::new(action, target, target_data);

    let proof = Proof::create(
        proof_base.key,
        proof_base.expires_in + proof_base.now,
        action,
        proof_base.nonce,
        empty_packed(),
    );

    Encoded::from_encodable(proof)
}

/// Ensure that the selection is sorted.
pub fn create_read_some_proof(
    proof_base: ProofBaseView,
    selection: Vec<String>,
) -> Encoded<Proof<()>> {
    let action = ActionType::ReadUsers;
    let target = Target::Select;
    let target_data = TargetList::from_vec(selection);
    let action = ProofAction::new(action, target, target_data);

    let proof = Proof::create(
        proof_base.key,
        proof_base.expires_in + proof_base.now,
        action,
        proof_base.nonce,
        empty_packed(),
    );

    Encoded::from_encodable(proof)
}

pub fn create_read_range_proof(
    proof_base: ProofBaseView,
    selection: Vec<String>,
) -> Encoded<Proof<()>> {
    if selection.len() != 2 {
        panic!("Range should include exactly two elements!")
    }

    let action = ActionType::ReadUsers;
    let target = Target::Range;
    let target_data = TargetList::from_vec(selection);

    let action = ProofAction::new(action, target, target_data);

    let proof = Proof::create(
        proof_base.key,
        proof_base.expires_in + proof_base.now,
        action,
        proof_base.nonce,
        empty_packed(),
    );

    Encoded::from_encodable(proof)
}
