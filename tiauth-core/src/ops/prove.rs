use crate::crypto::{self, sign_data, verify_signature, Key};
use crate::data::{app_key, state_table, Claims, Session};
use crate::error::WrapErrorOneOf;
use crate::state::State;
use crate::util::nonce_384;
use base64::{engine::general_purpose as b64, Engine as _};
use rand::rngs::StdRng;
use redb::{Error as DbError, ReadableTable, WriteTransaction};
use rmp_serde::{decode, encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::str;
use std::time::SystemTime;
use terrors::OneOf;
use thiserror::Error;

#[derive(PartialEq, Eq)]
pub enum ProofUseVerify {
    ResetPassword,
    SetClaims,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "use")]
pub enum ProofUse {
    ResetPassword { user_id: String },
    SetClaims { user_id: String, claims: Claims },
}

impl ProofUse {
    fn encode(&self) -> String {
        let encoded = encode::to_vec_named(self).unwrap();

        b64::URL_SAFE_NO_PAD.encode(encoded)
    }

    pub fn verify_type(&self, verifier: ProofUseVerify) -> bool {
        match verifier {
            ProofUseVerify::ResetPassword => matches!(self, ProofUse::ResetPassword { .. }),
            ProofUseVerify::SetClaims => matches!(self, ProofUse::SetClaims { .. }),
        }
    }

    pub fn unwrap_user_id(&self) -> &str {
        match self {
            ProofUse::SetClaims { user_id, .. } => user_id,
            ProofUse::ResetPassword { user_id } => user_id, // _ => panic!("ProofUse must be SetClaims or ResetPassword variant!")
        }
    }

    pub fn unwrap_claims(self) -> Claims {
        match self {
            ProofUse::SetClaims { claims, .. } => claims,
            _ => panic!("ProofUse must be SetClaims variant!"),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct ProofInfo {
    /// Nonce ensures it is used just once
    pub nonce: String,
    pub expires: u64,
    pub application: String,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Proof {
    /// For (de)serialization, the inner fields are put into the main Proof struct
    #[serde(flatten)]
    pub info: ProofInfo,
    pub proof_use: ProofUse,
    // This signature is base64url-encoded.
    pub signature: String,
}

impl Proof {
    fn create(
        rng: &mut StdRng,
        app_key: &Key,
        application: &str,
        expires_in: Option<u64>,
        proof_use: ProofUse,
    ) -> Self {
        let nonce = nonce_384(rng);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = expires_in.unwrap_or(1800) + now;

        let info = ProofInfo {
            nonce,
            expires,
            application: application.to_owned(),
        };

        let data = proof_data(&info, &proof_use);

        let signature = sign_data(app_key, &data);

        let signature = b64::URL_SAFE_NO_PAD.encode(signature);

        Proof {
            info,
            proof_use,
            signature,
        }
    }
}

pub fn proof_data(info: &ProofInfo, proof_use: &ProofUse) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        info.application,
        info.nonce,
        info.expires,
        proof_use.encode()
    )
    .into_bytes()
}

pub const LEEWAY: u64 = 10;

#[derive(Debug)]
pub struct InvalidSession {}

pub fn verify_session(state: &mut State, session: &[u8]) -> Result<Session, InvalidSession> {
    let session =
        crypto::session_decrypt(session, &state.private.session).map_err(|_e| InvalidSession {})?;

    decode::from_read(session.as_slice()).map_err(|_e| InvalidSession {})
}

#[derive(Error, Debug)]
#[error("Invalid proof.")]
pub struct InvalidProof {}

/// This checks all parts of the proof that do not require reading inspecting the state table.
/// It is still required to check if the nonce has already been used!
pub fn verify_proof_meta(
    state: &mut State,
    proof: Proof,
    verify_use: ProofUseVerify,
) -> Result<(ProofInfo, ProofUse), OneOf<(DbError, InvalidProof)>> {
    if !proof.proof_use.verify_type(verify_use) {
        return Err(OneOf::new(InvalidProof {}));
    }

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > proof.info.expires + LEEWAY {
        return Err(OneOf::new(InvalidProof {}));
    };

    let key = app_key(state, &proof.info.application).to_one_of_two()?;

    let signature = b64::URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .map_err(|_e| OneOf::new(InvalidProof {}))?;

    let is_verified = verify_signature(&proof_data(&proof.info, &proof.proof_use), &signature, key);

    if !is_verified {
        return Err(OneOf::new(InvalidProof {}));
    }

    Ok((proof.info, proof.proof_use))
}

pub fn verify_proof_write(
    state: &mut State,
    write_txn: &WriteTransaction,
    proof_info: &ProofInfo,
) -> Result<(), OneOf<(DbError, InvalidProof)>> {
    let state_table_def = state_table(state.tables, &proof_info.application);

    let mut state_table = write_txn.open_table(state_table_def).to_one_of_two()?;
    {
        // TODO clean up nonces every so often (after expiry)
        let nonce_exists = state_table.get(proof_info.nonce.as_str()).to_one_of_two()?;

        if nonce_exists.is_some() {
            return Err(OneOf::new(InvalidProof {}));
        }
    }

    let proof_expires = format!("{}", proof_info.expires);
    state_table
        .insert(proof_info.nonce.as_str(), proof_expires.as_str())
        .to_one_of_two()?;

    Ok(())
}

pub mod test_util {
    use crate::configure::test_util::create_register_app;

    use super::*;

    pub fn create_proof(
        rng: &mut StdRng,
        app_key: &Key,
        application: &str,
        expires_in: Option<u64>,
        proof_use: ProofUse,
    ) -> Proof {
        Proof::create(rng, app_key, application, expires_in, proof_use)
    }

    pub fn register_proof_claims(
        state: &mut State,
        application: &str,
        user_id: &str,
        expires_in: Option<u64>,
        claims: Claims,
    ) -> Proof {
        let key = create_register_app(state, application);

        let proof_use = ProofUse::SetClaims {
            user_id: user_id.to_owned(),
            claims,
        };

        Proof::create(state.rng, &key, application, expires_in, proof_use)
    }
}

#[cfg(test)]
mod tests {
    use test_util::register_proof_claims;

    use super::*;

    use crate::ops::login::test_util::*;
    use crate::state::StateOwner;

    #[test]
    fn test_login_session() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let claims = Claims::new(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);

        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let claims_proof = register_proof_claims(&mut state, app, user_id, None, claims);

        let session = login_create_session(
            &mut state,
            user_id,
            app,
            password,
            Some(claims_proof),
            Some(vec!["email"]),
        );

        let session = verify_session(&mut state, &session).unwrap();

        let claims = session.session_claims.get();

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
