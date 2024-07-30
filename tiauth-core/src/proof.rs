use crate::crypto::{self, sign_data, verify_signature, EphemeralKey, Key, PublicKey, SessionKey};
use crate::data::LEEWAY;
use crate::data::{
    AboutVerify, ByteSerial, InvalidProof, ProofContent, SerializedAs, SessionContent,
};
use crate::encoded::Encodable;
use crate::error::OneOfTo;
use crate::util::{combine_encode, rmp_read_bin, rmp_read_str};
use crate::{ActionType, ByteOwned, BytePacked, Claims, Target, TargetList};
use base64::{engine::general_purpose as b64, Engine as _};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use std::io::Cursor;
use std::marker::PhantomData;
use terrors::OneOf;

#[derive(Debug)]
/// A proof is issued by the application using their private key and verified using the public key stored inside `tiauth`. 
pub struct Proof<T> {
    phantom: PhantomData<T>,
    content: Vec<u8>,
    signature: Vec<u8>,
}

impl<T> Encodable for Proof<T> {
    type Error = InvalidProof;

    fn decode(encoded: &str) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut bytes = match b64::URL_SAFE_NO_PAD.decode(encoded) {
            Ok(bytes) => bytes,
            Err(_) => {
                println!("invalid decode");
                return Err(InvalidProof {});
            }
        };
        let total_len = bytes.len();
        if total_len < 4 {
            println!("shorter than 4 bytes, no content length.");
            return Err(InvalidProof {});
        }
        let ln = &bytes[(total_len - 4)..total_len];
        let content_length = u32::from_le_bytes([ln[0], ln[1], ln[2], ln[3]]) as usize;
        if total_len < 4 + 64 + content_length {
            println!("Not long enough to content content and valid signature.");
            return Err(InvalidProof {});
        }
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
    nonce: impl SerializedAs<Ephemeral<()>>,
    data: impl SerializedAs<T>,
    key: &Key,
    now: u64
) -> Proof<T> {
    let expires = expires_in + now;
    let content = ProofContent::new(
        application,
        expires,
        action,
        target,
        target_data,
        nonce.serialized(),
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
    time: u64,
) -> Result<ProofContent<'a, T>, OneOf<(InvalidProof,)>> {
    let proof_input: ProofContent<T> = ProofContent::from_bytes(&proof_bytes.content)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    if verify.verify(&proof_input.about).is_err() {
        println!("bad action");
        return Err(OneOf::new(InvalidProof {}));
    }

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
    time: u64,
) -> Session {
    let expires = expires_in + time;
    let content = SessionContent::new(
        application,
        user_id,
        time,
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
pub struct InvalidSession;

pub fn verify_session_bytes(
    session_encrypted: &Session,
    key: &SessionKey,
) -> Result<VerifiedSession, InvalidSession> {
    let session_decrypted = crypto::session_decrypt(&session_encrypted.encrypted_bytes, key)
        .map_err(|_e| InvalidSession {})?;

    Ok(VerifiedSession(session_decrypted))
}


#[derive(PartialEq, Eq, Debug)]
pub enum EphemeralType {
    NewUser,
    ChangePassword,
    SetPassword,
    Login,
    ProofToken
}

#[derive(Error, Debug)]
#[error("Invalid EphemeralType.")]
pub struct InvalidEphemeral;




pub trait EphemeralStateType {
    type VerifyType<'a>;

    fn valid_type(eph_type: &EphemeralType) -> Result<(), InvalidEphemeral> {
        if !Self::is_valid_type(eph_type) {
            return Err(InvalidEphemeral)
        }

        Ok(())
    }

    fn is_valid_type(eph_type: &EphemeralType) -> bool;

    /// Return the state in a form that is necessary for the comparison. This can also be bytes.
    fn get_state<'a>(state: &'a [u8]) -> Self::VerifyType<'a>;

    /// Create a binary representation of the state that should be compared when verifying the Ephemeral.
    fn create_state(self) -> impl AsRef<[u8]>;
}

pub struct EphemeralCounterState {
    pub count: u64,
    pub expires: u64
}

pub struct EphemeralChangePasswordState {
    pub password_file: String
}

pub struct EphemeralEmptyState;

impl EphemeralStateType for EphemeralEmptyState {
    type VerifyType<'a> = ();

    fn is_valid_type(eph_type: &EphemeralType) -> bool {
        eph_type == &EphemeralType::NewUser
    }

    fn get_state<'a>(_: &'a [u8]) -> Self::VerifyType<'a> {
        ()
    }

    fn create_state(self) -> impl AsRef<[u8]> {
        []
    }
}

impl EphemeralStateType for EphemeralCounterState {
    fn is_valid_type(eph_type: &EphemeralType) -> bool {
        eph_type == &EphemeralType::ProofToken || eph_type == &EphemeralType::Login
    }

    /// This function panics if the state is not exactly 16 bytes.
    fn get_state(state: &[u8]) -> Self {
        assert_eq!(state.len(), 16);
        let counter_bytes: [u8; 8] = state[0..8].try_into().unwrap();
        let expires_bytes: [u8; 8] = state[8..16].try_into().unwrap();

        Self { count: u64::from_le_bytes(counter_bytes), expires: u64::from_le_bytes(expires_bytes) }
    }
    
    fn create_state(self) -> impl AsRef<[u8]> {
        let mut state_bytes = [0u8; 16];
        state_bytes[0..8].copy_from_slice(&self.count.to_le_bytes());
        state_bytes[8..16].copy_from_slice(&self.expires.to_le_bytes());

        state_bytes
    }
    
    type VerifyType<'a> = Self;
    
}

impl EphemeralStateType for EphemeralChangePasswordState {
    fn is_valid_type(eph_type: &EphemeralType) -> bool {
        eph_type == &EphemeralType::ChangePassword
    }
    
    type VerifyType<'a> = &'a [u8];
    
    fn get_state<'a>(state: &'a [u8]) -> Self::VerifyType<'a> {
        state
    }
    
    fn create_state(self) -> impl AsRef<[u8]> {
        let mut hasher = Sha256::new();
        hasher.update(self.password_file.as_bytes());
        hasher.finalize()
    }

}

impl EphemeralType {
    pub fn is(&self) -> impl Fn(&EphemeralType) -> bool + '_ {
        |t: &EphemeralType| t.key_name() == self.key_name()
    }

    fn try_get_state<'a, S: EphemeralStateType>(&self, state: &'a [u8]) -> Result<S::VerifyType<'a>, InvalidEphemeral> {
        S::valid_type(&self)?;

        Ok(S::get_state(state))
    }

    fn key_name(&self) -> &'static str {
        match self {
            Self::NewUser => "new_user",
            Self::ChangePassword => "change_pass",
            Self::SetPassword => "set_pass",
            Self::Login => "login",
            Self::ProofToken => "proof_token"
        }
    }

    fn from_key_name(key_name: &str) -> Result<Self, InvalidEphemeral> {
        let eph_type = match key_name {
            "new_user" => Self::NewUser,
            "change_pass" => Self::ChangePassword,
            "set_pass" => Self::SetPassword,
            "login" => Self::Login,
            "proof_token" => Self::ProofToken,
            _ => return Err(InvalidEphemeral),
        };

        Ok(eph_type)
    }
}

#[derive(Debug)]
pub struct Ephemeral<T: ByteSerial> {
    phantom: PhantomData<T>,
    content: Vec<u8>,
    tag: [u8; 32]
}

pub struct EphemeralView<'a, T: ByteSerial> {
    phantom: PhantomData<T>,
    content: &'a [u8],
    tag: &'a [u8; 32]
}

impl<'a, T: ByteSerial> EphemeralView<'a, T> {
    pub fn verify(
        &self,
        verify_keys: &[EphemeralKey],
        application: &str,
    ) -> Result<EphemeralContent<'a, T>, InvalidEphemeral> {
        let Self { tag, content, .. } = self;

        Ephemeral::verify_components(tag, content, verify_keys, application)
    }
}

impl<T: ByteSerial + 'static> ByteSerial for Ephemeral<T> {
    type Deserialized<'a> = EphemeralView<'a, T>;

    type DeserializeErr = InvalidEphemeral;

    fn serialize(&self) -> crate::ByteOwned<Self>
    where
        Self: Sized {
        let mut bytes = self.content.clone();
        bytes.extend_from_slice(&self.tag);
        ByteOwned::new(bytes)
    }

    fn try_deserialize(bytes: &[u8]) -> Result<Self::Deserialized<'_>, Self::DeserializeErr> {
        if bytes.len() < 32 {
            return Err(InvalidEphemeral)
        }

        let (content, tag) = bytes.split_at(bytes.len()-32);
        let tag: &[u8; 32] = tag.try_into().unwrap();

        Ok(Self::Deserialized {
            phantom: PhantomData,
            content,
            tag
        })
    }

    fn try_deserialize_owned(bytes: &[u8]) -> Result<Self, Self::DeserializeErr>
    where
        Self: Sized {
        if bytes.len() < 32 {
            return Err(InvalidEphemeral)
        }

        let (content, tag) = bytes.split_at(bytes.len()-32);
        let tag: [u8; 32] = tag.try_into().unwrap();

        Ok(Self { phantom: PhantomData, content: content.to_vec(), tag })

    }
}

impl<T: ByteSerial> Encodable for Ephemeral<T> {
    type Error = InvalidEphemeral;

    fn decode(encoded: &str) -> Result<Self, Self::Error>
    {
        let mut bytes = match b64::URL_SAFE_NO_PAD.decode(encoded) {
            Ok(bytes) => bytes,
            Err(_) => {
                println!("invalid decode");
                return Err(InvalidEphemeral);
            }
        };
        let total_len = bytes.len();
        if total_len < 4 {
            println!("shorter than 4 bytes, no content length.");
            return Err(InvalidEphemeral);
        }
        let ln = &bytes[(total_len - 4)..total_len];
        let content_length = u32::from_le_bytes([ln[0], ln[1], ln[2], ln[3]]) as usize;
        if total_len < 4 + 32 + content_length {
            println!("Not long enough for content and valid tag.");
            return Err(InvalidEphemeral);
        }
        // After this the original contains only the content
        let tag_vec = bytes.split_off(content_length);
        if tag_vec.len() + 4 != 36 {
            println!("Incorrect length for content length and tag.");
            return Err(InvalidEphemeral);
        }
        let tag: [u8; 32] = (&tag_vec[0..32]).try_into().unwrap();

        Ok(Self {
            phantom: PhantomData,
            content: bytes,
            tag,
        })
    }

    fn encode(&self) -> String {
        let content_length: [u8; 4] = (self.content.len() as u32).to_le_bytes();
        let total_len = content_length.len() + self.content.len() + self.tag.len();

        combine_encode(
            &[&self.content, &self.tag, &content_length],
            total_len,
        )
    }
}

impl<T: ByteSerial> Ephemeral<T> {
    pub fn create<S: EphemeralStateType>(
        key: &EphemeralKey,
        user_id: &str,
        application: &str,
        state: S,
        eph_type: EphemeralType,
        data: &BytePacked<T>,
    ) -> Self {
        assert!(S::is_valid_type(&eph_type));
        let state = state.create_state();
        let ephemeral = EphemeralContent {
            user_id,
            application,
            state: state.as_ref(),
            eph_type,
            data,
        };

        let serialized = ephemeral.serialize();

        let tag = crypto::ephemeral(&serialized, key);

        Self {
            phantom: PhantomData,
            content: serialized,
            tag
        }
    }

    fn verify_components<'a, 'tag>(
        tag: &'tag [u8; 32],
        content: &'a [u8],
        verify_keys: &[EphemeralKey],
        application: &str,
    ) -> Result<EphemeralContent<'a, T>, InvalidEphemeral> {
        crypto::verify_ephemeral(content, verify_keys, tag).map_err(|_| InvalidEphemeral)?;

        let content = EphemeralContent::deserialize(content)?;

        if content.application != application {
            return Err(InvalidEphemeral);
        }

        Ok(content)
    }

    /// Checks if the content of the Ephemeral was indeed created using one of the verify keys. It does not check for re-use.
    pub fn verify<'a>(
        &'a self,
        verify_keys: &[EphemeralKey],
        application: &str,
    ) -> Result<EphemeralContent<'a, T>, InvalidEphemeral> {
        let Self { tag, content, .. } = &self;

        Self::verify_components(tag, content, verify_keys, application)
    }
}

#[derive(Debug)]
pub struct EphemeralContent<'a, T: ByteSerial> {
    /// Allowed to be empty
    pub user_id: &'a str,
    pub application: &'a str,
    /// This can be used for the either the state itself or a hash of the state (based on the EphemeralType), the Ephemeral is only
    /// valid if the state is unchanged from when the Ephemeral was handed out
    state: &'a [u8],
    pub eph_type: EphemeralType,
    data: &'a BytePacked<T>,
}

// struct EphemeralVerify<'a> {
//     eph_type: EphemeralType,

// }

impl<'a, T: ByteSerial> EphemeralContent<'a, T> {
    pub fn new(
        user_id: &'a str,
        application: &'a str,
        state: &'a [u8],
        eph_type: EphemeralType,
        data: &'a BytePacked<T>,
    ) -> Self {
        Self {
            user_id,
            application,
            state,
            eph_type,
            data,
        }
    }

    pub fn verify_state<S: EphemeralStateType, F: FnOnce(S::VerifyType<'a>) -> Result<(), InvalidEphemeral>>(&self, verify: F) -> Result<T::Deserialized<'a>, InvalidEphemeral> {
        // This also checks if the eph_type is valid       
        let s: S::VerifyType<'a> = self.eph_type.try_get_state::<S>(&self.state)?;

        verify(s)?;

        Ok(self.data.deserialize())
    }

    pub fn verify_state_equal<S: EphemeralStateType>(&self, current_state_input: S) -> Result<T::Deserialized<'a>, InvalidEphemeral> {
        S::valid_type(&self.eph_type)?;
        
        let current_state = current_state_input.create_state();

        if current_state.as_ref() != self.state {
            return Err(InvalidEphemeral)
        }

        Ok(self.data.deserialize())
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        rmp::encode::write_array_len(&mut buf, 5).unwrap();
        rmp::encode::write_str(&mut buf, self.user_id).unwrap();
        rmp::encode::write_str(&mut buf, self.application).unwrap();
        rmp::encode::write_bin(&mut buf, self.state).unwrap();
        let eph_type = self.eph_type.key_name();
        rmp::encode::write_str(&mut buf, eph_type).unwrap();
        let data_bytes = self.data.as_bytes();
        rmp::encode::write_bin(&mut buf, data_bytes).unwrap();

        buf
    }

    pub fn deserialize(bytes: &'a [u8]) -> Result<Self, InvalidEphemeral> {
        let mut cursor = Cursor::new(bytes);

        let len = rmp::decode::read_array_len(&mut cursor).map_err(|_| InvalidEphemeral)?;
        if len != 5 {
            return Err(InvalidEphemeral);
        }
        let user_id = rmp_read_str(bytes, &mut cursor).map_err(|_| InvalidEphemeral)?;
        let application = rmp_read_str(bytes, &mut cursor).map_err(|_| InvalidEphemeral)?;
        let state = rmp_read_bin(bytes, &mut cursor).map_err(|_| InvalidEphemeral)?;
        let eph_type = rmp_read_str(bytes, &mut cursor).unwrap();
        let eph_type = EphemeralType::from_key_name(eph_type).map_err(|_| InvalidEphemeral)?;
        let data = rmp_read_bin(bytes, &mut cursor).map_err(|_| InvalidEphemeral)?;
        let data: &BytePacked<T> = BytePacked::new(data);
        Ok(Self {
            user_id,
            application,
            state,
            eph_type,
            data,
        })
    }
}