use bytes::Bytes;
use lazy_borink::Lazy;
use serde_bytes::ByteBuf;
use serde::{Deserialize, Serialize};
use tiauth_core::api::{admin, prove::Proof, State};
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

#[derive(Debug, Deserialize)]
pub struct GetUsers {
    pub application: String,
    pub proof: Lazy<Proof<()>>
}

pub async fn get_users_encoded(state: &impl State, request: GetUsers) -> Vec<u8> {
    let proof = request.proof.take();
    println!("{:?}", proof);
    match admin::get_users_encoded(state, &request.application, proof) {
        Ok(users) => encode::to_vec_named(&StructList::from_vec_vec(users)).unwrap(),
        Err(e) => match e.to_enum() {
            terrors::E2::A(e) => todo!(),
            terrors::E2::B(e) => todo!(),
        }
    }
}