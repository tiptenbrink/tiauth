//! reset:1:<user>
//! delete:1:<user>
//! set:<user>:
//! read:all
//! read:
//!
//! <application>:<expires>:<action_type>:<target>:<nonce>
//!
//! <target blob>
//! <permission blob>

use std::time::SystemTime;

use crate::crypto::{self, verify_signature, PublicKey};
use crate::data::{AboutVerify, InvalidProof, Proof, ProofContent};
use crate::data::{Session, LEEWAY};
use crate::error::WrapErrorOneOf;
use crate::state::State;
use crate::Tables;
use base64::{engine::general_purpose as b64, Engine as _};
use redb::{Error as DbError, ReadableTable, WriteTransaction};
use serde::{de::DeserializeOwned, Serialize};
use terrors::OneOf;

pub fn verify_proof_content<T>(
    proof: Proof<T>,
    public_key: &PublicKey,
    verify: AboutVerify,
) -> Result<ProofContent<T>, OneOf<(InvalidProof,)>>
where
    T: DeserializeOwned + Serialize + core::fmt::Debug,
{
    let (mut lazy_proof, signature) = proof.into_parts();

    // These are small and cheap to take out and clone
    // TODO propagate the decode error?
    let about = lazy_proof.inner().about.clone();

    if verify.application != about.application {
        return Err(OneOf::new(InvalidProof {}));
    }
    if let Some(action) = verify.action {
        if action != about.action {
            return Err(OneOf::new(InvalidProof {}));
        }
    }

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > about.expires + LEEWAY {
        return Err(OneOf::new(InvalidProof {}));
    };

    if verify_signature(lazy_proof.bytes(), &signature, public_key) {
        Ok(lazy_proof.take())
    } else {
        Err(OneOf::new(InvalidProof {}))
    }
}

pub fn verify_proof_write<T>(
    state: &impl State,
    write_txn: &WriteTransaction,
    content: &mut ProofContent<T>,
) -> Result<(), OneOf<(DbError, InvalidProof)>> {
    let tables = state.tables().app(&content.about.application);
    let nonce = b64::URL_SAFE_NO_PAD.encode(&content.nonce);
    let mut eph_table = write_txn.open_table(tables.ephemeral()).to_one_of_two()?;
    {
        // TODO clean up nonces every so often (after expiry)

        let nonce_exists = eph_table.get(nonce.as_str()).to_one_of_two()?;

        if nonce_exists.is_some() {
            return Err(OneOf::new(InvalidProof {}));
        }
    }

    let proof_expires = format!("{}", content.about.expires);
    eph_table
        .insert(nonce.as_str(), proof_expires.as_str())
        .to_one_of_two()?;

    Ok(())
}

pub fn verify_proof<T>(
    state: &impl State,
    proof: Proof<T>,
    verify: AboutVerify,
) -> Result<ProofContent<T>, OneOf<(DbError, InvalidProof)>>
where
    T: Serialize + DeserializeOwned + core::fmt::Debug,
{
    let key = state.app_key(&verify.application);
    let mut proof_content = verify_proof_content(proof, &key, verify).map_err(OneOf::broaden)?;

    let write_txn = state.db().begin_write().to_one_of_two()?;

    verify_proof_write(state, &write_txn, &mut proof_content)?;

    write_txn.commit().to_one_of_two()?;

    Ok(proof_content)
}

#[derive(Debug)]
pub struct InvalidSession {}

pub fn verify_session(state: &impl State, session: &[u8]) -> Result<Session, InvalidSession> {
    let session = crypto::session_decrypt(session, &state.private().session)
        .map_err(|_e| InvalidSession {})?;

    rmp_serde::decode::from_read(session.as_slice()).map_err(|_e| InvalidSession {})
}

#[cfg(test)]
pub mod test_util {
    use crate::data::EXPIRE_TIME;
    use crate::data::{ActionType, Claims, Session, Target, TargetList};
    use crate::state::test_util::*;
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
    ) -> Proof<Claims> {
        let expires_in = expires_in.unwrap_or(1800);
        let key = state.proof_key(application);

        Proof::new(
            application,
            expires_in,
            ActionType::Set,
            Target::Select,
            TargetList::user(user_id),
            claims.into(),
            key,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        data::{ActionType, Claims, ProofAbout},
        state::test_util::*,
    };

    use serde::Deserialize;
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

        let claims = session.session_claims.0;

        assert_eq!(
            claims
                .iter()
                .filter(|(k, v)| {
                    *k == "email" && std::str::from_utf8(v).unwrap() == "hi@abc.nl"
                })
                .count(),
            1
        );

        assert_eq!(claims.len(), 2);
    }

    #[derive(Debug, Deserialize)]
    struct ProofContentAttempt {
        #[serde(flatten)]
        pub about: ProofAbout,
    }

    // #[derive(Debug, Deserialize)]
    // struct ProofContentAttempt {
    //     #[serde(flatten)]
    //     pub about: ProofAbout,
    // }

    #[test]
    fn test_proof_verify() {
        let user_id = "hi";
        let app = "abc";

        let state = TestState::setup_test(vec![app]);
        let claims = Claims::new(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);
        let proof = create_proof_claims(&state, app, user_id, None, claims.clone());

        let mut proof_content = verify_proof(
            &state,
            proof.clone(),
            AboutVerify::new(app, ActionType::Set),
        )
        .unwrap();

        let unwrapped_claims = proof_content.data.inner();

        assert_eq!(claims.0, unwrapped_claims.0);
        assert_eq!(app, proof_content.about.application);
    }
}
