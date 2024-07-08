use crate::crypto::{self, sign_data, verify_signature, Key, PublicKey, SessionKey};
use crate::data::LEEWAY;
use crate::data::{
    AboutVerify, ByteSerial, InvalidProof, ProofContent, SerializedAs, SessionContent,
};
use crate::util::combine_encode;
use crate::encoded::Encodable;
use crate::{ActionType, Claims, Target, TargetList};
use base64::DecodeError;
use base64::{engine::general_purpose as b64, Engine as _};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::marker::PhantomData;
/// This is necessary because SystemTime is not implemented on the WASM target. The web_time crate calls Date.now() instead.
#[cfg(any(not(target_arch = "wasm32"), not(target_os = "unknown")))]
use std::time::SystemTime;
use terrors::OneOf;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use web_time::SystemTime;

#[derive(Debug)]
pub struct Proof<T> {
    phantom: PhantomData<T>,
    content: Vec<u8>,
    signature: Vec<u8>,
}

impl<T> Encodable for Proof<T> {
    type Error = DecodeError;

    fn decode(encoded: &str) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut bytes = b64::URL_SAFE_NO_PAD.decode(encoded)?;
        let total_len = bytes.len();
        let ln = &bytes[(total_len - 4)..total_len];
        let content_length = u32::from_le_bytes([ln[0], ln[1], ln[2], ln[3]]) as usize;
        // After this the original contains only the content
        let mut signature = bytes.split_off(content_length);
        signature.truncate(signature.len() - 4);

        Ok(Self {
            phantom: PhantomData,
            content: bytes,
            signature,
        })
    }

    fn encode(&self) -> String {
        let content_length: [u8; 4] = (self.content.len() as u32).to_le_bytes();
        let total_len = content_length.len() + self.content.len() + self.signature.len();

        combine_encode(
            &[&self.content, &self.signature, &content_length],
            total_len,
        )
    }
}

pub fn create_proof<T: ByteSerial>(
    application: &str,
    expires_in: u64,
    action: ActionType,
    target: Target,
    target_data: TargetList,
    data: impl SerializedAs<T>,
    key: &Key,
) -> Proof<T> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires = expires_in + now;
    let content = ProofContent::new(
        application,
        expires,
        action,
        target,
        target_data,
        data.serialized(),
    );

    write_proof(&content, key)
}

fn write_proof<T: ByteSerial>(proof_content: &ProofContent<T>, key: &Key) -> Proof<T> {
    let content = proof_content.to_bytes();
    let signature = sign_data(key, &content);

    Proof {
        content,
        signature,
        phantom: PhantomData,
    }
}

pub fn verify_proof_content<'a, T: ByteSerial>(
    proof_bytes: &'a Proof<T>,
    public_key: &PublicKey,
    verify: AboutVerify,
) -> Result<ProofContent<'a, T>, OneOf<(InvalidProof,)>> {
    let proof_input: ProofContent<T> = ProofContent::from_bytes(&proof_bytes.content);

    if verify.application != proof_input.about.application {
        println!("invalid app");
        return Err(OneOf::new(InvalidProof {}));
    }
    if let Some(action) = verify.action {
        if action != proof_input.about.action {
            println!("bad action");
            return Err(OneOf::new(InvalidProof {}));
        }
    }

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > proof_input.about.expires + LEEWAY {
        println!("expired");
        return Err(OneOf::new(InvalidProof {}));
    };

    if verify_signature(&proof_bytes.content, &proof_bytes.signature, public_key) {
        Ok(proof_input)
    } else {
        println!("invalid sig");
        Err(OneOf::new(InvalidProof {}))
    }
}

#[derive(Debug, PartialEq)]
pub struct Session {
    encrypted_bytes: Vec<u8>,
}

impl Session {
    pub fn into_encoded(&self) -> String {
        b64::URL_SAFE_NO_PAD.encode(&self.encrypted_bytes)
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.encrypted_bytes
    }
}

pub fn create_session(
    application: &str,
    user_id: &str,
    expires_in: u64,
    session_claims: impl SerializedAs<Claims>,
    key: &SessionKey,
) -> Session {
    let issued = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires = expires_in + issued;
    let content = SessionContent::new(
        application,
        user_id,
        issued,
        expires,
        session_claims.serialized(),
    );

    Session {
        encrypted_bytes: crypto::session(&content.to_bytes(), key, &mut StdRng::from_entropy()),
    }
}

pub struct VerifiedSession(Vec<u8>);

impl VerifiedSession {
    pub fn read(&self) -> Result<SessionContent, InvalidSession> {
        Ok(SessionContent::from_bytes(&self.0))
    }
}

#[derive(Debug)]
pub struct InvalidSession {}

pub fn verify_session_bytes(
    session_encrypted: &Session,
    key: &SessionKey,
) -> Result<VerifiedSession, InvalidSession> {
    let session_decrypted = crypto::session_decrypt(&session_encrypted.encrypted_bytes, key)
        .map_err(|_e| InvalidSession {})?;

    Ok(VerifiedSession(session_decrypted))
}
