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

use lazy_borink::Lazy;
use rand::rngs::StdRng;
use rand::SeedableRng;
use redb::{Error as DbError, ReadableTable, WriteTransaction};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use terrors::OneOf;
use thiserror::Error;
use crate::crypto::{self, sign_data, verify_signature, Key, PublicKey};
use crate::data::{Claims, Session, Tables};
use crate::error::WrapErrorOneOf;
use crate::state::State;
use crate::util::{nonce_384, nonce_384_bytes};
use base64::{engine::general_purpose as b64, Engine as _};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum ActionType {
    #[serde(rename = "reset")]
    Reset,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "set")]
    Set,
    #[serde(rename = "read")]
    Read
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
pub enum Target {
    #[serde(rename = "select")]
    Select,
    #[serde(rename = "all")]
    All,
}

impl Target {
    fn name(&self) -> &'static str {
        match &self {
            Self::Select => "select",
            Self::All => "all",
        }   
    }
}

impl ActionType {
    fn name(&self) -> &'static str {
        match &self {
            Self::Reset => "reset",
            Self::Delete => "delete",
            Self::Set => "set",
            Self::Read => "read"
        }   
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProofAbout {
    pub application: String,
    pub expires: u64,
    pub action: ActionType,
    pub target: Target
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProofContent<T> {
    #[serde(flatten)]
    pub about: ProofAbout,
    pub nonce: Vec<u8>,
    pub target_data: Lazy<Vec<String>>,
    // TODO see if we can prevent this by fixing lazy-borink
    #[serde(bound(deserialize = "T: DeserializeOwned"))]
    pub data: Lazy<T>
}

impl<T> ProofContent<T> {
    pub fn new(application: &str, expires: u64, action: ActionType, target: Target, target_data: Lazy<Vec<String>>, data: Lazy<T>) -> Self {
        let nonce = nonce_384_bytes(&mut StdRng::from_entropy());

        Self {
            about: ProofAbout {
                application: application.to_owned(),
                expires,
                action,
                target
            },
            nonce,
            target_data,
            data
        }
    }
}


#[derive(Debug, Serialize, Deserialize, Clone)]
struct ProofInner<T> {
    #[serde(bound(deserialize = "T: DeserializeOwned"))]
    proof: Lazy<ProofContent<T>>,
    signature: Vec<u8>
}

impl<T> ProofInner<T> 
    where T: Serialize
{
    fn new(proof_content: ProofContent<T>, key: &Key) -> Self {
        let mut proof_content = Lazy::from_inner(proof_content);
    
        let signature = sign_data(key, proof_content.bytes());
    
        Self {
            proof: proof_content,
            signature
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(transparent)]
pub struct Proof<T> {
    #[serde(bound(deserialize = "T: DeserializeOwned"))]
    inner: ProofInner<T>
}

pub struct TargetList(Lazy<Vec<String>>);

impl TargetList {
    pub fn new<S: AsRef<str>>(vec: Vec<S>) -> Self {
        Self(Lazy::from_inner(vec.into_iter().map(|s| s.as_ref().to_owned()).collect()))
    }

    pub fn user(user_id: &str) -> Self {
        Self::new(vec![user_id])
    }
    
    pub fn from_vec(vec: Vec<String>) -> Self {
        Self(Lazy::from_inner(vec))
    }
}

impl From<Lazy<Vec<String>>> for TargetList {
    fn from(value: Lazy<Vec<String>>) -> Self {
        Self(value)
    }
}

impl<T> Proof<T> 
    where T: Serialize
{
    pub fn new(application: &str, expires_in: u64, action: ActionType, target: Target, target_data: TargetList, data: Lazy<T>, key: &Key) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = expires_in + now;
        
        let proof_content = ProofContent::new(application, expires, action, target, target_data.0, data);
        
        Self {
            inner: ProofInner::new(proof_content, key)
        }
    }

    pub fn into_encoded(self) -> String {
        b64::URL_SAFE_NO_PAD.encode(&Lazy::from_inner(self.inner).take_bytes())
    }

    // pub fn create_encoded(application: &str, expires: u64, action: ActionType, target: Target, target_data: Lazy<Vec<String>>, data: Lazy<T>, key: &Key) -> String {
    //     let proof_content = ProofContent::new(application, expires, action, target, target_data, data);
    //     let inner = ProofInner::new(proof_content, key);

    //     b64::URL_SAFE_NO_PAD.encode(&Lazy::from_inner(inner).take_bytes())
    // }

    pub fn into_parts(self) -> (Lazy<ProofContent<T>>, Vec<u8>) {
        (self.inner.proof, self.inner.signature)
    }
}

pub struct AboutVerify {
    pub application: String,
    pub action: Option<ActionType>,
}

impl AboutVerify {
    pub fn new(application: &str, action: Option<ActionType>) -> Self {
        Self {
            application: application.to_owned(),
            action
        }
    }
}

#[derive(Error, Debug)]
#[error("Invalid proof.")]
pub struct InvalidProof {}

fn verify_proof_content<T>(proof: Proof<T>, public_key: &PublicKey, verify: AboutVerify) -> Result<ProofContent<T>, InvalidProof>
    where T: DeserializeOwned + Serialize
{
    let (mut lazy_proof, signature) = proof.into_parts();

    // These are small and cheap to take out and clone
    // TODO propagate the decode error?
    let about = lazy_proof.inner().about.clone();

    if verify.application != about.application {
        return Err(InvalidProof {})
    }
    if let Some(action) = verify.action {
        if action != about.action {
            return Err(InvalidProof {})
        }
    }
    
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > about.expires + LEEWAY {
        return Err(InvalidProof {});
    };

    if verify_signature(
        lazy_proof.bytes(),
        &signature,
        public_key,
    ) {
        Ok(lazy_proof.take())
    } else {
        Err(InvalidProof {})
    }
}


pub fn verify_proof_write<T>(
    state: &impl State,
    write_txn: &WriteTransaction,
    content: &mut ProofContent<T>
) -> Result<(), OneOf<(DbError, InvalidProof)>> {
    let tables = state.tables().app(&content.about.application);
    let nonce = b64::URL_SAFE_NO_PAD.encode(&content.nonce);
    let mut state_table = write_txn.open_table(tables.state()).to_one_of_two()?;
    {
        // TODO clean up nonces every so often (after expiry)
        
        let nonce_exists = state_table.get(nonce.as_str()).to_one_of_two()?;

        if nonce_exists.is_some() {
            return Err(OneOf::new(InvalidProof {}));
        }
    }

    let proof_expires = format!("{}", content.about.expires);
    state_table
        .insert(nonce.as_str(), proof_expires.as_str())
        .to_one_of_two()?;

    Ok(())
}


fn verify_proof<T>(
    state: &impl State,
    proof: Proof<T>,
    verify: AboutVerify,
) -> Result<ProofContent<T>, OneOf<(DbError, InvalidProof)>> 
    where T: Serialize + DeserializeOwned
{
    let key = state.app_key(&verify.application);
    let mut proof_content = verify_proof_content(proof, &key, verify).to_one_of_twond()?;

    let write_txn = state.db().begin_write().to_one_of_two()?;

    verify_proof_write(state, &write_txn, &mut proof_content)?;

    write_txn.commit().to_one_of_two()?;

    Ok(proof_content)
}

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

    rmp_serde::decode::from_read(session.as_slice()).map_err(|_e| InvalidSession {})
}

#[cfg(test)]
pub mod test_util {
    use crate::data::Session;
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
    ) -> Proof<Claims> {
        let expires_in = expires_in.unwrap_or(1800);
        let key = state.proof_key(application);

        Proof::new(application, expires_in, ActionType::Set, Target::Select, TargetList::user(user_id), claims.into(), key)
    }
}

#[cfg(test)]
mod tests {
    use crate::state::test_util::*;

    use lazy_borink::UnwrapLazy;
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

        let mut proof_content =
            verify_proof(&state, proof.clone(), AboutVerify::new(app, Some(ActionType::Set))).unwrap();

        let unwrapped_claims = proof_content.data.inner();

        assert_eq!(claims.0, unwrapped_claims.0);
        assert_eq!(app, proof_content.about.application);
    }
}