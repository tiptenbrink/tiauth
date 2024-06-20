use bytes::Bytes;
use serde_bytes::ByteBuf;
use serde::{Deserialize, Serialize};
use tiauth_core::api::{admin, Proof, State};
use rmp_serde::{decode, encode};

#[derive(Serialize, Deserialize)]
pub struct StructList {
    list: Vec<ByteBuf>
}

impl StructList {
    fn from_vec_vec(vec_vec: Vec<Vec<u8>>) -> Self {
        Self {
            list: vec_vec.into_iter().map(|v| ByteBuf::from(v)).collect()
        }
        
    }
}

pub async fn get_users_encoded(state: &impl State, request: Bytes) -> Vec<u8> {
    let proof: Proof = decode::from_slice(&request).unwrap();
    match admin::get_users_encoded(state, proof) {
        Ok(users) => encode::to_vec_named(&StructList::from_vec_vec(users)).unwrap(),
        Err(e) => match e.to_enum() {
            terrors::E2::A(e) => todo!(),
            terrors::E2::B(e) => todo!(),
        }
    }
}