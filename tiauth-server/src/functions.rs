
use tiauth_core::api::{register, State};
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct PakeRequest {
    pub application: String,
    pub request: String,
    pub user_id: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PakeResponse {
    pub response: String,
    pub nonce: String
}

pub async fn start_register(state: &impl State, request: PakeRequest) -> PakeResponse {
    match register::start_register(state, &request.application, &request.request, &request.user_id) {
        Ok((response, nonce)) => PakeResponse { response, nonce },
        Err(e) => match e.to_enum() {
            terrors::E2::A(e) => todo!(),
            terrors::E2::B(e) => todo!(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PakeFinishRequest {
    pub application: String,
    pub request: String,
    pub nonce: String,

}

pub async fn register_finish(state: &impl State, request: PakeFinishRequest) {
    match register::register_finish(state, &request.application, &request.request, &request.nonce, None) {
        Ok(()) => (),
        Err(e) => match e.to_enum() {
            terrors::E4::A(e) => todo!(),
            terrors::E4::B(e) => todo!(),
            terrors::E4::C(e) => todo!(),
            terrors::E4::D(e) => todo!(),
        }
    }
}