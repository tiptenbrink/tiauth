use crate::api::Tables;
use crate::crypto::{self, sign_data, verify_signature, Key};
use crate::data::{Claims, Session};
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
    DeleteUser,
    SetClaims,
    ReadAll
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
#[serde(tag = "use")]
pub enum ProofUse {
    ResetPassword { user_id: String },
    SetClaims { user_id: String, claims: Claims },
    DeleteUser { user_id: String },
    ReadAll
}

impl ProofUse {
    fn encode(&self) -> String {
        let encoded = encode::to_vec_named(self).unwrap();

        b64::URL_SAFE_NO_PAD.encode(encoded)
    }

    pub fn verify_type(&self, verifier: ProofUseVerify) -> bool {
        match verifier {
            ProofUseVerify::DeleteUser => matches!(self, ProofUse::DeleteUser { .. }),
            ProofUseVerify::ResetPassword => matches!(self, ProofUse::ResetPassword { .. }),
            ProofUseVerify::SetClaims => matches!(self, ProofUse::SetClaims { .. }),
            ProofUseVerify::ReadAll => matches!(self, ProofUse::ReadAll),
        }
    }

    pub fn unwrap_user_id(&self) -> &str {
        match self {
            ProofUse::DeleteUser { user_id } => user_id,
            ProofUse::SetClaims { user_id, .. } => user_id,
            ProofUse::ResetPassword { user_id } => user_id, 
            _ => panic!("ProofUse {:?} has no user_id!", self)
        }
    }

    pub fn unwrap_claims(self) -> Claims {
        match self {
            ProofUse::SetClaims { claims, .. } => claims,
            _ => panic!("ProofUse must be SetClaims variant!"),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
pub struct ProofInfo {
    /// Nonce ensures it is used just once
    pub nonce: String,
    pub expires: u64,
    pub application: String,
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
pub struct Proof {
    /// For (de)serialization, the inner fields are put into the main Proof struct
    #[serde(flatten)]
    pub info: ProofInfo,
    pub proof_use: ProofUse,
    // This signature is base64url-encoded.
    pub signature: String,
}

impl Proof {
    pub fn create(
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

// How outdated a session or other time-sensitive token is allowed to be
pub const LEEWAY: u64 = 10;

// Can only delete account with session that is less than 10 minutes old
pub const DELETE_AGE: u64 = 600;

// Can only change password with session that is less than 10 minutes old
pub const CHANGE_AGE: u64 = 600;

#[derive(Debug)]
pub struct InvalidSession {}

pub fn verify_session(state: &impl State, session: &[u8]) -> Result<Session, InvalidSession> {
    let session = crypto::session_decrypt(session, &state.private().session)
        .map_err(|_e| InvalidSession {})?;

    decode::from_read(session.as_slice()).map_err(|_e| InvalidSession {})
}

#[derive(Error, Debug)]
#[error("Invalid proof.")]
pub struct InvalidProof {}

/// This checks all parts of the proof that do not require reading inspecting the state table.
/// It is still required to check if the nonce has already been used!
pub fn verify_proof_meta(
    state: &impl State,
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

    let signature = b64::URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .map_err(|_e| OneOf::new(InvalidProof {}))?;

    let is_verified = verify_signature(
        &proof_data(&proof.info, &proof.proof_use),
        &signature,
        &state.app_key(&proof.info.application),
    );

    if !is_verified {
        return Err(OneOf::new(InvalidProof {}));
    }

    Ok((proof.info, proof.proof_use))
}

pub fn verify_proof_write(
    state: &impl State,
    write_txn: &WriteTransaction,
    proof_info: &ProofInfo,
) -> Result<(), OneOf<(DbError, InvalidProof)>> {
    let tables = state.tables().app(&proof_info.application);

    let mut state_table = write_txn.open_table(tables.state()).to_one_of_two()?;
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

fn verify_proof(
    state: &impl State,
    proof: Proof,
    verify_use: ProofUseVerify,
) -> Result<(ProofInfo, ProofUse), OneOf<(DbError, InvalidProof)>> {
    let (proof_info, proof_use) = verify_proof_meta(state, proof, verify_use)?;

    let write_txn = state.db().begin_write().to_one_of_two()?;

    verify_proof_write(state, &write_txn, &proof_info)?;

    write_txn.commit().to_one_of_two()?;

    Ok((proof_info, proof_use))
}

#[cfg(test)]
pub mod test_util {
    use crate::state::test_util::*;
    use crate::EXPIRE_TIME;
    use std::time::UNIX_EPOCH;

    use super::*;

    pub fn create_session(user_id: &str, application: &str, session_claims: Claims) -> Session {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Session {
            user_id: user_id.to_owned(),
            application: application.to_owned(),
            issued: time,
            expires: time + EXPIRE_TIME,
            session_claims,
        }
    }

    pub fn create_proof_claims(
        state: &TestState,
        application: &str,
        user_id: &str,
        expires_in: Option<u64>,
        claims: Claims,
    ) -> Proof {
        let proof_use = ProofUse::SetClaims {
            user_id: user_id.to_owned(),
            claims,
        };

        Proof::create(
            &mut state.rng(),
            state.proof_key(application),
            application,
            expires_in,
            proof_use,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::state::test_util::*;

    use test_util::*;

    use super::*;

    #[test]
    fn test_session_verify() {
        let user_id = "hi";
        let app = "abc";

        let state = TestState::setup_test(vec![app]);

        let claims = Claims::new(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);

        let session = create_session(user_id, app, claims);

        let session = verify_session(
            &state,
            &session.token(&state.private().session, &mut state.rng()),
        )
        .unwrap();

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

        assert_eq!(claims.len(), 2);
    }

    #[test]
    fn test_proof_verify() {
        let user_id = "hi";
        let app = "abc";

        let state = TestState::setup_test(vec![app]);
        let claims = Claims::new(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);
        let proof = create_proof_claims(&state, app, user_id, None, claims.clone());

        let (proof_info, proof_use) =
            verify_proof(&state, proof.clone(), ProofUseVerify::SetClaims).unwrap();

        let unwrapped_claims = proof_use.unwrap_claims();

        assert_eq!(claims.get(), unwrapped_claims.get());
        assert_eq!(proof.info.application, proof_info.application);
    }
}
