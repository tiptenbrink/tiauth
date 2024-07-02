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

use std::io::Read;
use std::marker::PhantomData;
use std::time::SystemTime;

use crate::crypto::{self, sign_data, verify_signature, Key, PublicKey, SessionKey};
use crate::data::{AboutVerify, ByteOwned, BytePacked, ByteSerial, InvalidProof, ProofContent, SerializedAs, SessionContent};
use crate::data::{LEEWAY};
use crate::error::WrapErrorOneOf;
use crate::state::State;
use crate::{ActionType, Claims, Tables, Target, TargetList};
use base64::{engine::general_purpose as b64, Engine as _};
use rand::rngs::StdRng;
use rand::SeedableRng;
use redb::{Error as DbError, ReadableTable, WriteTransaction};
use serde::{de::DeserializeOwned, Serialize};
use terrors::OneOf;

pub struct Proof<T> {
    phantom: PhantomData<T>,
    content: Vec<u8>,
    signature: Vec<u8>
}

/// Efficiently encode multiple slices into a base64url string, allocating O(n) only once, otherwise only allocating for a maximum of 3 bytes at the boundary of the slices.
fn combine_encode(inputs: &[&[u8]], total_len: usize) -> String {
    let total_triplets = total_len / 3;
    let max_str_len = (total_triplets+1) * 4;

    let mut buf: Vec<u8> = Vec::with_capacity(max_str_len);
    let mut position: usize = 0;
    let mut remaining: Vec<u8> = Vec::with_capacity(3);
    for slice in inputs {
        let mut slice = *slice;
        let slice_len = slice.len();
        if slice_len == 0 {
            continue;
        }

        if remaining.len() > 0 {
            let necessary = 3 - remaining.len();
            if slice_len >= necessary {
                let slice_taken = &slice[0..necessary];
                // Remove used bytes from slice
                slice = &slice[necessary..slice_len];
                // Remaining is now always 3 bytes
                remaining.extend_from_slice(slice_taken);
                assert_eq!(remaining.len(), 3);
                let mut buf_slice = &mut buf[position..(position+3)];
                b64::URL_SAFE.encode_slice(&remaining, &mut buf_slice).unwrap();
                // 4 characters per 3 bytes
                position += 4;
                remaining = Vec::with_capacity(3);
            } else {
                // slice_len and remaining_len must be 1, otherwise it would always have enough
                assert_eq!(slice_len, 1);
                assert_eq!(remaining.len(), 1);

                remaining[1] = slice[0];
                // We can continue since we dealt with the slice
                continue;
            }
        }
        // Now remaining is always empty
        assert_eq!(remaining.len(), 0);

        let slice_len = slice.len();
        let slice_triplets = slice_len / 3;
        let slice_triplet_len = slice_triplets * 3;
        let remainder = slice_len - slice_triplet_len;
        remaining.extend_from_slice(&slice[slice_triplet_len..slice_len]);
        assert_eq!(remainder, remaining.len());

        let slice_aligned = &slice[0..slice_triplet_len];
        let buf_added = slice_triplets * 4;
        let mut buf_slice = &mut buf[position..(position+buf_added)];
        b64::URL_SAFE.encode_slice(&slice_aligned, &mut buf_slice).unwrap();
        position += buf_added;
    }


    let last_part = b64::URL_SAFE_NO_PAD.encode(&remaining);
    buf.extend_from_slice(last_part.as_bytes());

    String::from_utf8(buf).unwrap()
}

impl<T> Proof<T> {
    pub fn into_encoded(self) -> String {
        let content_length: [u8; 4] = (self.content.len() as u32).to_le_bytes();
        let total_len = content_length.len() + self.content.len() + self.signature.len();
        
        combine_encode(&[&content_length, &self.content, &self.signature], total_len)
    }
}

pub fn create_proof<T: ByteSerial>(application: &str,
    expires_in: u64,
    action: ActionType,
    target: Target,
    target_data: TargetList,
    data: impl SerializedAs<T>,
    key: &Key) -> Proof<T> {
    let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    let expires = expires_in + now;
    let content = ProofContent::new(application, expires, action, target, target_data, data.serialized());

    write_proof(&content, key)
}

fn write_proof<T: ByteSerial>(proof_content: &ProofContent<T>, key: &Key) -> Proof<T> {
    let content = proof_content.to_bytes();
    let signature = sign_data(key, &content);

    Proof { content, signature, phantom: PhantomData }
}

pub fn verify_proof_content<'a, 'b, T: ByteSerial>(
    proof_bytes: &'a Proof<T>,
    public_key: &'b PublicKey,
    verify: AboutVerify,
) -> Result<ProofContent<'a, T>, OneOf<(InvalidProof,)>>

{
    let proof_input: ProofContent<T> = ProofContent::from_bytes(&proof_bytes.content);

    // let (mut lazy_proof, signature) = proof.into_parts();

    // // These are small and cheap to take out and clone
    // // TODO propagate the decode error?
    // let about = lazy_proof.inner().about.clone();

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

pub fn create_session(application: &str,
    user_id: &str,
    expires_in: u64,
    session_claims: impl SerializedAs<Claims>,
    key: &SessionKey) -> Session {
    let issued = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    let expires = expires_in + issued;
    let content = SessionContent::new(application, user_id, issued, expires, session_claims.serialized());

    Session {
        encrypted_bytes: crypto::session(&content.to_bytes(), key, &mut StdRng::from_entropy())
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

pub fn verify_session<'a, 'b>(state: &impl State, session_encrypted: &Session) -> Result<VerifiedSession, InvalidSession> {
    let session_decrypted = crypto::session_decrypt(&session_encrypted.encrypted_bytes, &state.private().session)
        .map_err(|_e| InvalidSession {})?;

    Ok(VerifiedSession(session_decrypted))
}



#[cfg(feature = "test")]
pub mod test_util {
    use crate::data::{BytePacked, SerializedAs, EXPIRE_TIME};
    use crate::data::{ActionType, Claims, Target, TargetList};
    use crate::state::test_util::*;
    use std::time::UNIX_EPOCH;

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

        create_proof(application, expires_in, ActionType::Set, Target::Select, TargetList::user(user_id), claims, key)
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

        let session = create_session(user_id, app, EXPIRE_TIME, claims.serialize(), &state.private().session);

        let session = verify_session(
            &state,
            &session,
        )
        .unwrap();

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

        let proof_content = verify_proof(
            &state,
            &proof,
            AboutVerify::new(app, ActionType::Set),
        )
        .unwrap();

        let deser_claims = proof_content.data.deserialize();

        assert!(claims.eq_view(&deser_claims));
        assert_eq!(app, proof_content.about.application);
    }
}
