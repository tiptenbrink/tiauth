#![allow(dead_code)]

use crate::crypto::{self, load_public_key, sign_data, Key, PublicKey, SavedPublicKey, SessionKey};
use crate::util::nonce_384_bytes;
use base64::{engine::general_purpose as b64, Engine as _};
use serde_bytes::ByteBuf;
use lazy_borink::Lazy;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rmp_serde::encode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::str;
/// This is necessary because SystemTime is not implemented on the WASM target. The web_time crate calls Date.now() instead.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use web_time::SystemTime;
#[cfg(any(not(target_family="wasm"), not(target_os="unknown")))]
use std::time::SystemTime;
use terrors::OneOf;
use thiserror::Error;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct ClaimsBytes(ByteBuf);

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Login {
    pub user_id: String,
    pub password_file: String,
    pub claims: Lazy<Claims>,
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
#[serde(transparent)]
#[derive(Default)]
pub struct Claims(pub HashMap<String, Vec<u8>>);

impl Claims {
    pub fn new<S, V>(map: Vec<(S, V)>) -> Self
    where
        S: Into<String>,
        V: AsRef<[u8]>,
    {
        Self(HashMap::from_iter(
            map.into_iter()
                .map(|(s, v)| (s.into(), v.as_ref().to_vec())),
        ))
    }

    pub fn none() -> Self {
        Self(HashMap::new())
    }

    /// Returns only claims with keys in the provided subset. Consumes the previous claims object.
    pub fn into_subset<S>(mut self, subset: Vec<S>) -> Self
    where
        S: AsRef<str>,
    {
        Self(HashMap::from_iter(
            subset
                .iter()
                .filter_map(|s| self.0.remove_entry(s.as_ref())),
        ))
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Session {
    pub user_id: String,
    pub application: String,
    pub issued: u64,
    pub expires: u64,
    /// These are a subset of the "login claims"
    /// They are a msgpack map
    pub session_claims: Claims,
}

impl Session {
    pub fn token(&self, session_key: &SessionKey, rng: &mut StdRng) -> Vec<u8> {
        let session_encoded = encode::to_vec_named(&self).unwrap();

        crypto::session(&session_encoded, session_key, rng)
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Application {
    // This must be a
    public_key: String,
    pub name: String,
}

impl Application {
    pub fn new(saved_public_key: SavedPublicKey, name: &str) -> Self {
        Self {
            public_key: saved_public_key.pem(),
            name: name.to_owned(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        // We safely unwrap because it can only have been constructed with SavedPublicKey
        load_public_key(&self.public_key).unwrap()
    }
}

// 1 month
pub const EXPIRE_TIME: u64 = 30 * 24 * 60 * 60;

pub const LEEWAY: u64 = 10;

// Can only delete account with session that is less than 10 minutes old
pub const DELETE_AGE: u64 = 600;

// Can only change password with session that is less than 10 minutes old
pub const CHANGE_AGE: u64 = 600;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum ActionType {
    #[serde(rename = "reset")]
    Reset,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "set")]
    Set,
    #[serde(rename = "read")]
    Read,
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
            Self::Read => "read",
        }
    }
}

#[derive(Error, Debug)]
#[error("Invalid proof.")]
pub struct InvalidProof {}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProofAbout {
    pub application: String,
    pub expires: u64,
    pub action: ActionType,
    pub target: Target,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProofContent<T> {
    #[serde(flatten)]
    pub about: ProofAbout,
    pub nonce: Vec<u8>,
    pub target_data: Lazy<Vec<String>>,
    // TODO see if we can prevent this by fixing lazy-borink
    #[serde(bound(deserialize = "T: DeserializeOwned"))]
    pub data: Lazy<T>,
}

impl<T> ProofContent<T> {
    pub fn new(
        application: &str,
        expires: u64,
        action: ActionType,
        target: Target,
        target_data: Lazy<Vec<String>>,
        data: Lazy<T>,
    ) -> Self {
        let nonce = nonce_384_bytes(&mut StdRng::from_entropy());

        Self {
            about: ProofAbout {
                application: application.to_owned(),
                expires,
                action,
                target,
            },
            nonce,
            target_data,
            data,
        }
    }

    pub fn select_one(&mut self) -> Result<String, OneOf<(InvalidProof,)>> {
        let targets = self.target_data.inner();

        match self.about.target {
            Target::Select => {
                if targets.len() == 1 {
                    Ok(targets[0].clone())
                } else {
                    Err(OneOf::new(InvalidProof {}))
                }
            }
            Target::All => Err(OneOf::new(InvalidProof {})),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ProofInner<T> {
    #[serde(bound(deserialize = "T: DeserializeOwned"))]
    proof: Lazy<ProofContent<T>>,
    signature: Vec<u8>,
}

impl<T> ProofInner<T>
where
    T: Serialize + core::fmt::Debug,
{
    fn new(proof_content: ProofContent<T>, key: &Key) -> Self {
        let mut proof_content = Lazy::from_inner(proof_content);
        let signature = sign_data(key, proof_content.bytes());

        Self {
            proof: proof_content,
            signature,
        }
    }
}

/// Proof is not meant to be serializable, as it should be opaque and serialized only as bytes, e.g. using Lazy.
#[derive(Debug, Deserialize, Clone)]
#[serde(transparent)]
pub struct Proof<T> {
    #[serde(bound(deserialize = "T: DeserializeOwned"))]
    inner: ProofInner<T>,
}

pub struct TargetList(Lazy<Vec<String>>);

impl TargetList {
    pub fn new<S: AsRef<str>>(vec: Vec<S>) -> Self {
        Self(Lazy::from_inner(
            vec.into_iter().map(|s| s.as_ref().to_owned()).collect(),
        ))
    }

    pub fn user(user_id: &str) -> Self {
        Self::new(vec![user_id])
    }

    pub fn from_vec(vec: Vec<String>) -> Self {
        Self(Lazy::from_inner(vec))
    }

    pub fn empty() -> Self {
        Self(Vec::new().into())
    }
}

impl From<Lazy<Vec<String>>> for TargetList {
    fn from(value: Lazy<Vec<String>>) -> Self {
        Self(value)
    }
}

impl<T> Proof<T>
where
    T: Serialize + core::fmt::Debug,
{
    pub fn new(
        application: &str,
        expires_in: u64,
        action: ActionType,
        target: Target,
        target_data: TargetList,
        data: Lazy<T>,
        key: &Key,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = expires_in + now;
        let proof_content =
            ProofContent::new(application, expires, action, target, target_data.0, data);

        Self {
            inner: ProofInner::new(proof_content, key),
        }
    }

    pub fn into_encoded(self) -> String {
        b64::URL_SAFE_NO_PAD.encode(Lazy::from_inner(self.inner).take_bytes())
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
    pub fn new(application: &str, action: ActionType) -> Self {
        Self {
            application: application.to_owned(),
            action: Some(action),
        }
    }
}
