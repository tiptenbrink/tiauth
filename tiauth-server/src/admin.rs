use rmp_serde::encode;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tiauth_core::{admin, Proof, State};

use crate::encoded3::Encoded;

#[derive(Serialize)]
pub struct StructList {
    list: Vec<ByteBuf>,
}

impl StructList {
    fn from_vec_vec(vec_vec: Vec<Vec<u8>>) -> Self {
        Self {
            list: vec_vec.into_iter().map(ByteBuf::from).collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GetUsers {
    pub application: String,
    pub read_all_proof: Encoded<Proof<()>>,
}

pub async fn get_users_encoded(state: &impl State, request: GetUsers) -> Vec<u8> {
    let proof = request.read_all_proof.get();
    //println!("{:?}", proof);
    match admin::get_users_encoded(state, &request.application, &proof) {
        Ok(users) => encode::to_vec_named(&StructList::from_vec_vec(users)).unwrap(),
        Err(e) => match e.to_enum() {
            terrors::E2::A(_e) => todo!(),
            terrors::E2::B(_e) => todo!(),
        },
    }
}
