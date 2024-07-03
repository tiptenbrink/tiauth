use crate::encoded::Encoded;
use serde::{Deserialize, Serialize};
use tiauth_core::{register, login, Claims, Proof, State};

#[derive(Debug, Serialize, Deserialize)]
pub struct PakeRequest {
    pub application: String,
    pub opaque_request: String,
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PakeResponse {
    pub opaque_response: String,
    pub register_start_nonce: String,
}

pub async fn start_register(state: &impl State, request: PakeRequest) -> PakeResponse {
    match register::start_register(
        state,
        &request.application,
        &request.opaque_request,
        &request.user_id,
    ) {
        Ok((opaque_response, register_start_nonce)) => PakeResponse {
            opaque_response,
            register_start_nonce,
        },
        Err(e) => match e.to_enum() {
            terrors::E2::A(_e) => todo!(),
            terrors::E2::B(_e) => todo!(),
        },
    }
}

#[derive(Debug, Deserialize)]
pub struct PakeFinishRequest {
    pub application: String,
    pub opaque_request: String,
    pub register_start_nonce: String,
    pub claims_proof: Option<Encoded<Proof<Claims>>>,
}

pub async fn register_finish(state: &impl State, request: PakeFinishRequest) {
    let proof = request.claims_proof.map(|e| e.get());

    match register::register_finish(
        state,
        &request.application,
        &request.opaque_request,
        &request.register_start_nonce,
        proof.as_ref(),
    ) {
        Ok(()) => (),
        Err(e) => match e.to_enum() {
            terrors::E4::A(_e) => todo!(),
            terrors::E4::B(_e) => todo!(),
            terrors::E4::C(_e) => todo!(),
            terrors::E4::D(_e) => todo!(),
        },
    }
}

// #[derive(Debug, Serialize, Deserialize)]
// pub struct PakeRequest {
//     pub application: String,
//     pub opaque_request: String,
//     pub user_id: String,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct PakeResponse {
//     pub opaque_response: String,
//     pub register_start_nonce: String,
// }

// pub async fn start_login(state: &impl State, request: PakeRequest) -> PakeResponse {
//     match login::login_start(
//         state,
//         &request.application,
//         &request.opaque_request,
//         &request.user_id,
//     ) {
//         Ok((opaque_response, register_start_nonce)) => PakeResponse {
//             opaque_response,
//             register_start_nonce,
//         },
//         Err(e) => match e.to_enum() {
//             terrors::E2::A(_e) => todo!(),
//             terrors::E2::B(_e) => todo!(),
//         },
//     }
// }

#[cfg(feature = "app")]
mod appfn {
    //! In the future maybe allow apps to request proofs over TLS or similar
}
