use crate::model::GetUsers;
use rmp_serde::encode;
use tiauth_core::{admin, State};

pub fn get_users_encoded(state: &impl State, request: GetUsers) -> Vec<u8> {
    let proof = request.read_proof.get();

    //println!("{:?}", proof);
    match admin::get_users_bytes(state, &proof, request.include_claims.unwrap_or(false), request.include_password.unwrap_or(false)) {
        Ok(users) => encode::to_vec(&users).unwrap(),
        Err(e) => match e.to_enum() {
            terrors::E3::A(_) => todo!(),
            terrors::E3::B(_) => todo!(),
            terrors::E3::C(_) => todo!(),
        },
    }
}
