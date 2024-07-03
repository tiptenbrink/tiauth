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

use std::marker::PhantomData;
use std::time::SystemTime;

use crate::crypto::{self, sign_data, verify_signature, Key, PublicKey, SessionKey};
use crate::data::LEEWAY;
use crate::data::{
    AboutVerify, ByteSerial, InvalidProof, ProofContent, SerializedAs, SessionContent,
};
use crate::error::WrapErrorOneOf;
use crate::state::State;
use crate::util::combine_encode;
use crate::{ActionType, Claims, Tables, Target, TargetList};
use base64::{engine::general_purpose as b64, Engine as _};
use rand::rngs::StdRng;
use rand::SeedableRng;
use redb::{Error as DbError, ReadableTable, WriteTransaction};
use terrors::OneOf;



pub fn verify_proof_write<T: ByteSerial>(
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

pub fn verify_proof<'a, T: ByteSerial>(
    state: &impl State,
    proof: &'a Proof<T>,
    verify: AboutVerify,
) -> Result<ProofContent<'a, T>, OneOf<(DbError, InvalidProof)>>
where
{
    let key = state.app_key(&verify.application);
    let mut proof_content = verify_proof_content(proof, &key, verify).map_err(OneOf::broaden)?;

    let write_txn = state.db().begin_write().to_one_of_two()?;

    verify_proof_write(state, &write_txn, &mut proof_content)?;

    write_txn.commit().to_one_of_two()?;

    Ok(proof_content)
}



pub struct VerifiedSession(Vec<u8>);

impl VerifiedSession {
    pub fn read(&self) -> Result<SessionContent, InvalidSession> {
        Ok(SessionContent::from_bytes(&self.0))
    }
}

#[derive(Debug)]
pub struct InvalidSession {}

pub fn verify_session(
    state: &impl State,
    session_encrypted: &Session,
) -> Result<VerifiedSession, InvalidSession> {
    let session_decrypted =
        crypto::session_decrypt(&session_encrypted.encrypted_bytes, &state.private().session)
            .map_err(|_e| InvalidSession {})?;

    Ok(VerifiedSession(session_decrypted))
}

#[cfg(feature = "test")]
pub mod test_util {
    use crate::data::SerializedAs;
    use crate::data::{ActionType, Claims, Target, TargetList};
    use crate::state::test_util::*;

    use super::*;

    // pub fn create_session(user_id: &str, application: &str, session_claims: Claims) -> Session {
    //     let time = SystemTime::now()
    //         .duration_since(UNIX_EPOCH)
    //         .unwrap()
    //         .as_secs();

    //     Session {
    //         user_id: user_id.to_owned(),
    //         application: application.to_owned(),
    //         issued: time,
    //         expires: time + EXPIRE_TIME,
    //         session_claims,
    //     }
    // }

    pub fn create_proof_claims(
        state: &TestState,
        application: &str,
        user_id: &str,
        expires_in: Option<u64>,
        claims: impl SerializedAs<Claims>,
    ) -> Proof<Claims> {
        let expires_in = expires_in.unwrap_or(1800);
        let key = state.proof_key(application);

        create_proof(
            application,
            expires_in,
            ActionType::Set,
            Target::Select,
            TargetList::user(user_id),
            claims,
            key,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        data::{ActionType, Claims, ProofAbout, EXPIRE_TIME},
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

        let session = create_session(
            user_id,
            app,
            EXPIRE_TIME,
            claims.serialize(),
            &state.private().session,
        );

        let session = verify_session(&state, &session).unwrap();

        let session_read = session.read().unwrap();
        let session_claims = session_read.session_claims.deserialize();
        assert!(claims.eq_view(&session_claims));
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
        let proof = create_proof_claims(&state, app, user_id, None, claims.serialize());

        let proof_content =
            verify_proof(&state, &proof, AboutVerify::new(app, ActionType::Set)).unwrap();

        let deser_claims = proof_content.data.deserialize();

        assert!(claims.eq_view(&deser_claims));
        assert_eq!(app, proof_content.about.application);
    }
}
