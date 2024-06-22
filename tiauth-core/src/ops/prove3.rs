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
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::crypto::{self, sign_data, verify_signature, Key};
use crate::data::Claims;
use crate::state::State;
use crate::util::nonce_384;
use base64::{engine::general_purpose as b64, Engine as _};
use super::prove::InvalidProof;

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    pub nonce: String,
    pub target: Lazy<Vec<String>>,
    // TODO see if we can prevent this by fixing lazy-borink
    #[serde(bound(deserialize = "T: DeserializeOwned"))]
    pub data: Lazy<T>
}

impl<T> ProofContent<T> {
    pub fn new(application: &str, expires: u64, action: ActionType, target: Target, target_data: Lazy<Vec<String>>, data: Lazy<T>) -> Self {
        let nonce = nonce_384(&mut StdRng::from_entropy());

        Self {
            about: ProofAbout {
                application: application.to_owned(),
                expires,
                action,
                target
            },
            nonce,
            target: target_data,
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

impl<T> Proof<T> 
    where T: Serialize
{
    pub fn new(application: &str, expires_in: u64, action: ActionType, target: Target, target_data: Lazy<Vec<String>>, data: Lazy<T>, key: &Key) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = expires_in + now;
        
        let proof_content = ProofContent::new(application, expires, action, target, target_data, data);
        
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

fn verify_proof<T>(state: &impl State, proof: Proof<T>) -> Result<ProofContent<T>, InvalidProof>
    where T: DeserializeOwned + Serialize
{
    let (mut lazy_proof, signature) = proof.into_parts();
    
    // These are small and cheap to take out and clone
    // TODO propagate the decode error?
    let about = lazy_proof.inner().about.clone();
    
    // Do pre-signature checks

    if verify_signature(
        lazy_proof.bytes(),
        &signature,
        &state.app_key(&about.application),
    ) {
        Ok(lazy_proof.take())
    } else {
        Err(InvalidProof {})
    }
}

// nonce is in verify proof write

// there are kinda two ways to use Lazy