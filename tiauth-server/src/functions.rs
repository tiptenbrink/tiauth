
use lazy_borink::{Lazy, UnwrapLazy};
use tiauth_core::api::{register, Claims, Proof, State};
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose as b64, Engine as _};

#[derive(Debug, Serialize, Deserialize)]
pub struct PakeRequest {
    pub application: String,
    pub opaque_request: String,
    pub user_id: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PakeResponse {
    pub opaque_response: String,
    pub register_start_nonce: String
}

pub async fn start_register(state: &impl State, request: PakeRequest) -> PakeResponse {
    match register::start_register(state, &request.application, &request.opaque_request, &request.user_id) {
        Ok((opaque_response, register_start_nonce)) => PakeResponse { opaque_response, register_start_nonce },
        Err(e) => match e.to_enum() {
            terrors::E2::A(e) => todo!(),
            terrors::E2::B(e) => todo!(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PakeFinishRequest {
    pub application: String,
    pub opaque_request: String,
    pub register_start_nonce: String,
    pub claims_proof: Option<Lazy<Proof<Claims>>>
}

pub async fn register_finish(state: &impl State, request: PakeFinishRequest) {
    let proof: Option<Proof<Claims>> = request.claims_proof.map(|p| p.take());
    match register::register_finish(state, &request.application, &request.opaque_request, &request.register_start_nonce, proof) {
        Ok(()) => (),
        Err(e) => match e.to_enum() {
            terrors::E4::A(e) => todo!(),
            terrors::E4::B(e) => todo!(),
            terrors::E4::C(e) => todo!(),
            terrors::E4::D(e) => todo!(),
        }
    }
}