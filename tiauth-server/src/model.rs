use serde::{Deserialize, Serialize};
use tiauth_core::{encoded::Encoded, ByteOwned, Ephemeral};
use tiauth_core::Proof;

#[derive(Debug, Serialize, Deserialize)]
pub struct PakeRequest {
    pub application: String,
    pub opaque_request: String,
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartLoginResponse {
    pub opaque_response: String,
    pub start_nonce: Encoded<Ephemeral<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartRegisterResponse {
    pub opaque_response: String,
    pub start_nonce: Encoded<Ephemeral<()>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterFinishRequest {
    pub application: String,
    pub opaque_request: String,
    pub action_nonce: Encoded<Ephemeral<()>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginFinishRequest {
    pub application: String,
    pub opaque_request: String,
    pub start_nonce: Encoded<Ephemeral<String>>,
    pub pake_secret: String,
    pub all_claims: Option<bool>,
    pub requested_claims: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub session: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUsers {
    pub application: String,
    pub include_claims: Option<bool>,
    pub read_proof: Encoded<Proof<()>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResetPasswordRequest {
    pub application: String,
    pub reset_proof: Encoded<Proof<()>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofTokenRequest {
    pub application: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofTokenResponse {
    pub tokens: Encoded<ByteOwned<Ephemeral<()>>>,
}
