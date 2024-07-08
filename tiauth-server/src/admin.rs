use rmp_serde::encode;
use serde::Deserialize;
use tiauth_core::{admin, Proof, State};
use tiauth_core::encoded::Encoded;
use crate::{model::GetUsers};



pub async fn get_users_encoded(state: &impl State, request: GetUsers) -> Vec<u8> {
    let proof = request.read_proof.get();
    let include_claims = request.include_claims.unwrap_or(false);

    //println!("{:?}", proof);
    match admin::get_users_bytes(state, &request.application, include_claims, &proof) {
        Ok(users) => encode::to_vec_named(&users).unwrap(),
        Err(e) => match e.to_enum() {
            terrors::E2::A(_e) => todo!(),
            terrors::E2::B(_e) => todo!(),
        },
    }
}
