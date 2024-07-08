use tiauth_core::encoded::Encoded;
use serde::{Deserialize, Serialize};
use tiauth_core::{login, register, Claims, Proof, SessionClaims, State};
use crate::model::*;

pub fn start_register(state: &impl State, request: PakeRequest) -> PakeResponse {
    match register::start_register(
        state,
        &request.application,
        &request.opaque_request,
        &request.user_id,
    ) {
        Ok((opaque_response, start_nonce)) => PakeResponse {
            opaque_response,
            start_nonce,
        },
        Err(e) => match e.to_enum() {
            terrors::E2::A(_e) => todo!(),
            terrors::E2::B(_e) => todo!(),
        },
    }
}



pub fn register_finish(state: &impl State, request: RegisterFinishRequest) {
    let proof = request.claims_proof.map(|e| e.get());

    match register::register_finish(
        state,
        &request.application,
        &request.opaque_request,
        &request.start_nonce,
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

pub fn start_login(state: &impl State, request: PakeRequest) -> PakeResponse {
    match login::login_start(
        state,
        &request.application,
        &request.opaque_request,
        &request.user_id,
    ) {
        Ok((opaque_response, start_nonce)) => PakeResponse {
            opaque_response,
            start_nonce,
        },
        Err(e) => match e.to_enum() {
            terrors::E2::A(_e) => todo!(),
            terrors::E2::B(_e) => todo!(),
        },
    }
}



pub fn login_session(state: &impl State, request: LoginFinishRequest) -> SessionResponse {
    let session_claims =
        match SessionClaims::from_options(request.all_claims, request.requested_claims) {
            Ok(s) => s,
            Err(_e) => panic!(),
        };

    match login::login_session(
        state,
        &request.application,
        &request.opaque_request,
        &request.start_nonce,
        &request.pake_secret,
        session_claims,
    ) {
        Ok(session) => SessionResponse {
            session: session.into_encoded(),
        },
        Err(e) => match e.to_enum() {
            terrors::E2::A(_e) => todo!(),
            terrors::E2::B(_e) => todo!(),
        },
    }
}

#[cfg(feature = "app")]
mod appfn {
    //! In the future maybe allow apps to request proofs over TLS or similar
}
