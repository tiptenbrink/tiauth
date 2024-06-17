use crate::crypto::{self};
use crate::data::Session;
use crate::state::State;
use rmp_serde::decode;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::str;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum ProofUse {
    // String is user_id
    ResetPassword(String),

    CreateUser(String),
}

impl ProofUse {
    fn proof_repr(&self) -> String {
        match self {
            Self::ResetPassword(user_id) => format!("{}:reset_password", user_id).to_string(),
            Self::CreateUser(user_id) => format!("{}:create_user", user_id).to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Proof {
    /// Nonce ensures it is used just once
    pub nonce: String,
    pub expires: u64,
    pub application: String,
    pub proof_use: ProofUse,
    // This signature is base64url-encoded.
    pub signature: String,
}

pub fn proof_data(application: &str, nonce: &str, expires: u64, proof_use: &ProofUse) -> Vec<u8> {
    format!(
        "{}.{}.{}.{}",
        application,
        nonce,
        expires,
        proof_use.proof_repr()
    )
    .into_bytes()
}

pub const LEEWAY: u64 = 10;

#[derive(Debug)]
pub struct InvalidSession {}

fn verify_session_claims(state: &mut State, session: &[u8]) -> Result<Session, InvalidSession> {
    let session =
        crypto::session_decrypt(session, &state.private.session).map_err(|_e| InvalidSession {})?;

    decode::from_read(session.as_slice()).map_err(|_e| InvalidSession {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::login::test_util::*;
    use crate::state::StateOwner;
    use crate::util::msgpack_map;

    #[test]
    fn test_login_session() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let claims = msgpack_map(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);

        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let session = login_create_session(
            &mut state,
            user_id,
            app,
            password,
            Some(claims),
            Some(vec!["email"]),
        );

        let session = verify_session_claims(&mut state, &session).unwrap();

        let claims = session.session_claims.as_map().unwrap();

        assert_eq!(
            claims
                .iter()
                .filter(|(k, v)| {
                    k.as_str().unwrap() == "email" && v.as_str().unwrap() == "hi@abc.nl"
                })
                .count(),
            1
        );

        assert_eq!(claims.len(), 1);
    }
}
