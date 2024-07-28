use crate::crypto::{self, sign_data, verify_signature, EphemeralKey, Key, PublicKey, SessionKey};
use crate::data::LEEWAY;
use crate::data::{
    AboutVerify, ByteSerial, InvalidProof, ProofContent, SerializedAs, SessionContent,
};
use crate::encoded::Encodable;
use crate::error::OneOfTo;
use crate::util::{combine_encode, rmp_read_bin, rmp_read_str};
use crate::{ActionType, BytePacked, Claims, Target, TargetList};
use base64::{engine::general_purpose as b64, Engine as _};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use std::io::Cursor;
use std::marker::PhantomData;
#[cfg(any(not(target_arch = "wasm32"), not(target_os = "unknown")))]
use std::time::SystemTime;
/// This is necessary because SystemTime is not implemented on the WASM target. The web_time crate calls Date.now() instead.
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
    let proof_input: ProofContent<T> = ProofContent::from_bytes(&proof_bytes.content)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    if verify.verify(&proof_input.about).is_err() {
        println!("bad action");
        return Err(OneOf::new(InvalidProof {}));
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
}

#[derive(Error, Debug)]
#[error("Invalid EphemeralType.")]
pub struct InvalidEphemeral;

impl EphemeralType {
    pub fn is(&self) -> impl Fn(&EphemeralType) -> bool + '_ {
        |t: &EphemeralType| t.key_name() == self.key_name()
    }

    // The canonical Ephemeral state that is generated in case of change password. If the state is equal to the Ephemeral's actual state, then the Ephemeral has not been used.
    pub fn change_password_state(&self, password_file: &str) -> Vec<u8> {
        assert_eq!(self, &EphemeralType::ChangePassword);

        let mut hasher = Sha256::new();
        hasher.update(password_file.as_bytes());
        hasher.finalize().to_vec()
    }

    fn key_name(&self) -> &'static str {
        match self {
            Self::NewUser => "new_user",
            Self::ChangePassword => "change_pass",
            Self::SetPassword => "set_pass",
            Self::Login => "login",
        }
    }

    fn from_key_name(key_name: &str) -> Result<Self, InvalidEphemeral> {
        let eph_type = match key_name {
            "new_user" => Self::NewUser,
            "change_pass" => Self::ChangePassword,
            "set_pass" => Self::SetPassword,
            "login" => Self::Login,
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
    pub fn create(
        key: &EphemeralKey,
        user_id: &str,
        application: &str,
        state: &[u8],
        eph_type: EphemeralType,
        data: &BytePacked<T>,
    ) -> Self {
        let ephemeral = EphemeralContent {
            user_id,
            application,
            state,
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

    /// Checks if the content of the Ephemeral was indeed created using one of the verify keys. It does not check for re-use.
    pub fn verify<'a>(
        &'a self,
        verify_keys: &[EphemeralKey],
        application: &str,
    ) -> Result<EphemeralContent<'a, T>, InvalidEphemeral> {
        let Self { tag, content, .. } = &self;

        crypto::verify_ephemeral(content.as_slice(), verify_keys, tag).map_err(|_| InvalidEphemeral)?;

        let content = EphemeralContent::deserialize(content.as_slice())?;

        if content.application != application {
            return Err(InvalidEphemeral);
        }

        Ok(content)
    }
}

#[derive(Debug)]
pub struct EphemeralContent<'a, T: ByteSerial> {
    pub user_id: &'a str,
    pub application: &'a str,
    /// This can be used for the either the state itself or a hash of the state (based on the EphemeralType), the Ephemeral is only
    /// valid if the state is unchanged from when the Ephemeral was handed out
    pub state: &'a [u8],
    pub eph_type: EphemeralType,
    pub data: &'a BytePacked<T>,
}

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