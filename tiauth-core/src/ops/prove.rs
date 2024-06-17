use crate::crypto::{self, sign_data, Key, verify_signature};
use crate::data::{app_key, state_table, Session};
use crate::error::WrapErrorOneOf;
use crate::state::State;
use crate::util::nonce_384;
use rand::rngs::StdRng;
use redb::{Error, ReadableTable, WriteTransaction};
use rmp_serde::{decode, encode};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use terrors::OneOf;
use std::fmt::Debug;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::{engine::general_purpose as b64, Engine as _};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "use")]
pub enum ProofUse {
    // String is user_id
    ResetPassword(String),
    // String is user_id
    UserClaims(Value),
}

impl ProofUse {
    fn encode(&self) -> String {
        let encoded = encode::to_vec_named(self).unwrap();

        b64::URL_SAFE_NO_PAD.encode(encoded)
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

impl Proof {
    fn create(rng: &mut StdRng, app_key: &Key, application: &str, expires_in: Option<u64>, proof_use: ProofUse) -> Self {
        let nonce = nonce_384(rng);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = expires_in.unwrap_or(1800) + now;

        let data = proof_data(
           application,
            &nonce,
            expires,
            &proof_use,
        );

        let signature = sign_data(app_key, &data);

        let signature = b64::URL_SAFE_NO_PAD.encode(&signature);

        Proof {
            nonce,
            expires,
            application: application.to_owned(),
            proof_use,
            signature
        }
    }
}

pub fn proof_data(application: &str, nonce: &str, expires: u64, proof_use: &ProofUse) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        application,
        nonce,
        expires,
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

#[derive(Debug)]
pub struct InvalidProof {}

/// This checks all parts of the proof that do not require reading inspecting the state table.
/// It is still required to check if the nonce has already been used!
pub fn verify_proof_meta(state: &mut State, proof: &Proof) -> Result<(), OneOf<(InvalidProof, Error)>> {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > proof.expires + LEEWAY {
        return Err(OneOf::new(InvalidProof { }))
    };

    let key = app_key(state, &proof.application).to_one_of_twond()?;

    let signature = b64::URL_SAFE_NO_PAD.decode(&proof.signature).map_err(|_e| OneOf::new(InvalidProof { }))?;

    let is_verified = verify_signature(
        &proof_data(
            &proof.application,
            &proof.nonce,
            proof.expires,
            &proof.proof_use,
        ),
        &signature,
        key,
    );

    if !is_verified {
        return Err(OneOf::new(InvalidProof { }))
    }

    Ok(())
}

pub fn verify_proof_write(state: &mut State, write_txn: &WriteTransaction, proof: &Proof) -> Result<(), OneOf<(InvalidProof, Error)>> {
    let state_table_def = state_table(state.tables, &proof.application);
    
    let mut state_table = write_txn.open_table(state_table_def).to_one_of_twond()?;
    {
        // TODO clean up nonces every so often (after expiry)
        let nonce_exists = state_table.get(proof.nonce.as_str()).to_one_of_twond()?;

        if nonce_exists.is_some() {
            return Err(OneOf::new(InvalidProof { }))
        }
    }

    let proof_expires = format!("{}", proof.expires);
    state_table.insert(proof.nonce.as_str(), proof_expires.as_str()).to_one_of_twond()?;

    Ok(())
}

pub mod test_util {
    use super::*;

    pub fn create_proof(rng: &mut StdRng, app_key: &Key, application: &str, expires_in: Option<u64>, proof_use: ProofUse) -> Proof {
        Proof::create(rng, app_key, application, expires_in, proof_use)
    }

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

        let session = verify_session(&mut state, &session).unwrap();

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
