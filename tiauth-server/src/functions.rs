use crate::model::*;
use serde::Serialize;
use tiauth_core::{
    encoded::Encodable, ByteSerial,
};
use tiauth_core::{login, register, verify, SessionClaims, State};

pub fn proof_token(state: &impl State, _: ProofTokenRequest) -> ProofTokenResponse {
    let eph = verify::proof_token(state);

    ProofTokenResponse {
        tokens: eph.serialize().into_encoded(),
    }
}

pub fn start_register(state: &impl State, request: PakeRequest) -> StartRegisterResponse {
    match register::start_register(state, &request.opaque_request, &request.user_id) {
        Ok((opaque_response, start_nonce)) => StartRegisterResponse {
            opaque_response,
            start_nonce: start_nonce.into_encoded(),
        },
        Err(e) => match e.to_enum() {
            terrors::E1::A(_) => todo!(),
        },
    }
}

pub fn register_finish(state: &impl State, request: RegisterFinishRequest) {
    //let proof = request.claims_proof.map(|e| e.get());

    match register::register_finish(state, &request.opaque_request, &request.action_nonce.get()) {
        Ok(()) => (),
        Err(e) => match e.to_enum() {
            terrors::E4::A(_) => todo!(),
            terrors::E4::B(_) => todo!(),
            terrors::E4::C(_) => todo!(),
            terrors::E4::D(_) => todo!(),
        },
    }
}

pub fn start_login(state: &impl State, request: PakeRequest) -> StartLoginResponse {
    match login::login_start(state, &request.opaque_request, &request.user_id) {
        Ok((opaque_response, start_nonce)) => StartLoginResponse {
            opaque_response,
            start_nonce: start_nonce.into_encoded(),
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
        &request.opaque_request,
        &request.start_nonce.get(),
        &request.pake_secret,
        session_claims,
    ) {
        Ok(session) => SessionResponse {
            session: session.encode(),
        },
        Err(e) => match e.to_enum() {
            terrors::E4::A(_) => todo!(),
            terrors::E4::B(_) => todo!(),
            terrors::E4::C(_) => todo!(),
            terrors::E4::D(_) => todo!(),
        },
    }
}

// pub fn reset_password(state: &impl State, request: ResetPasswordRequest) {
//     let proof = request.reset_proof.get();

//     match modify::reset_password(state, &request.application, &proof) {
//         Ok(change_nonce) => {

//         }
//         Err(e) => todo!(),
//     }
// }
