use std::collections::HashMap;

use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};
use rmp_serde::decode;
use lazy_borink::Lazy;
use tiauth_core::crypto::{create_key, load_key, save_key, Key};
use base64::{engine::general_purpose as b64, Engine as _};
use tiauth_core::api::prove3::{Proof, ProofContent, ProofAbout, ActionType, Target};
use tiauth_core::api::Claims;

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
    //let data = Lazy::from_inner(Claims(claims));
    
    let proof = Proof::new(&proof_base.application, proof_base.expires_in, action, target, target_data, claims, &proof_base.key);

    proof.into_encoded()
}

// fn set_claims_proof_use<C: LazyOr<Claims>>(user_id: &str, claims: C) -> Lazy<ProofScope> {
//     let proof_use = ProofScope::SetClaims { user_id: user_id.to_owned(), claims: claims.as_lazy().take() };

//     Lazy::from_inner(proof_use)
// }

// fn create_proof_struct(proof_use: Lazy<ProofScope>, application: &str, private_key_pem: &str, expires_in: Option<u64>) -> Lazy<Proof> {
//     let key = load_key(private_key_pem);
    
//     Lazy::from_inner(Proof::create(&mut StdRng::from_entropy(), &key, application, expires_in, proof_use))
// }