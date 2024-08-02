use crate::crypto::{
    self, sign_data, verify_signature, AsSymmetricKey, Key, PublicKey, SymmetricKey,
};
use crate::data::{ByteSerial, SerializedAs};
use crate::data::{SessionKey, SessionStatus, EPHEMERAL_INTERVAL, LEEWAY};
use crate::encoded::Encodable;
use crate::error::OneOfTo;
use crate::util::{combine_encode, cursor_slice, rmp_read_bin, rmp_read_str};
use crate::{ByteOwned, BytePacked, Claims};
use base64::{engine::general_purpose as b64, Engine as _};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::io::Cursor;
use std::marker::PhantomData;
use terrors::OneOf;
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ActionType {
    ResetPassword,
    DeleteClaims,
    SetClaims,
    AddClaims,
    MergeClaims,
    ReadUsers,
    ReadPassword,
    DeleteUser,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Target {
    Select,
    Range,
    All,
}

impl Target {
    fn name(&self) -> &'static str {
        match &self {
            Self::Select => "select",
            Self::Range => "range",
            Self::All => "all",
        }
    }

    fn from_name(name: &str) -> Result<Self, InvalidProof> {
        Ok(match name {
            "select" => Self::Select,
            "range" => Self::Range,
            "all" => Self::All,
            _ => return Err(InvalidProof),
        })
    }
}

impl ActionType {
    fn name(&self) -> &'static str {
        match &self {
            ActionType::ResetPassword => "reset_password",
            ActionType::DeleteClaims => "delete_claims",
            ActionType::SetClaims => "set_claims",
            ActionType::AddClaims => "add_claims",
            ActionType::MergeClaims => "merge_claims",
            ActionType::ReadUsers => "read_users",
            ActionType::ReadPassword => "read_password",
            ActionType::DeleteUser => "delete_user",
        }
    }

    fn from_name(name: &str) -> Result<Self, InvalidProof> {
        Ok(match name {
            "reset_password" => ActionType::ResetPassword,
            "delete_claims" => ActionType::DeleteClaims,
            "set_claims" => ActionType::SetClaims,
            "add_claims" => ActionType::AddClaims,
            "merge_claims" => ActionType::MergeClaims,
            "read_users" => ActionType::ReadUsers,
            "read_password" => ActionType::ReadPassword,
            "delete_user" => ActionType::DeleteUser,
            _ => {
                eprintln!("ActionType {} does not exist!", name);
                return Err(InvalidProof);
            }
        })
    }
}

#[derive(Error, Debug)]
#[error("Invalid proof.")]
pub struct InvalidProof;

#[derive(Debug)]
pub struct ProofContent<'a, T>
where
    T: ByteSerial,
{
    action: ActionType,
    target: Target,
    target_data: TargetList,
    expires: u64,
    ephemeral: &'a BytePacked<Ephemeral<()>>,
    data: &'a BytePacked<T>,
}

pub struct ProofSingleTarget;

impl ProofTarget for ProofSingleTarget {
    type Output = String;

    fn validate(
        self,
        target: Target,
        mut target_data: TargetList,
    ) -> Result<Self::Output, InvalidProof> {
        Ok(match target {
            Target::Select => {
                if target_data.0.len() == 1 {
                    target_data.0.pop().unwrap()
                } else {
                    return Err(InvalidProof);
                }
            }
            _ => return Err(InvalidProof),
        })
    }
}

pub trait ProofTarget {
    type Output;

    fn validate(
        self,
        target: Target,
        target_data: TargetList,
    ) -> Result<Self::Output, InvalidProof>;
}

pub struct UnvalidatedProofObject<'a, T: ByteSerial> {
    pub action: ActionType,
    pub target: Target,
    target_data: TargetList,
    data: &'a BytePacked<T>,
}

pub trait ValidAction {
    fn action_valid(&self, action: ActionType) -> Result<(), InvalidProof> {
        if !self.is_action_valid(action) {
            return Err(InvalidProof);
        }

        Ok(())
    }

    fn is_action_valid(&self, action: ActionType) -> bool;
}

impl ValidAction for ActionType {
    fn is_action_valid(&self, action: ActionType) -> bool {
        self == &action
    }
}

impl ValidAction for Vec<ActionType> {
    fn is_action_valid(&self, action: ActionType) -> bool {
        self.contains(&action)
    }
}

impl<'a, T: ByteSerial> UnvalidatedProofObject<'a, T> {
    pub fn validate<P: ProofTarget>(
        self,
        action: impl ValidAction,
        proof_target: P,
    ) -> Result<(T::Deserialized<'a>, P::Output), InvalidProof> {
        let target_output = proof_target.validate(self.target, self.target_data)?;

        action.action_valid(self.action)?;

        let data = self.data.try_deserialize().map_err(|_| InvalidProof)?;

        Ok((data, target_output))
    }
}

// pub fn verify_proof_content<'a, T: ByteSerial>(
//     proof_bytes: &'a Proof<T>,
//     application: &str,
//     public_key: &PublicKey,
//     verify: AboutVerify,
//     time: u64,
// ) -> Result<ProofContent<'a, T>, OneOf<(InvalidProof,)>> {
//     let proof_input: ProofContent<T> = ProofContent::from_bytes(&proof_bytes.content)
//         .to_one_of()
//         .map_err(OneOf::broaden)?;

//     if verify.verify(&proof_input.about, application).is_err() {
//         println!("bad action");
//         return Err(OneOf::new(InvalidProof {}));
//     }

//     if time > proof_input.about.expires + LEEWAY {
//         println!("expired");
//         return Err(OneOf::new(InvalidProof {}));
//     };

//     if verify_signature(&proof_bytes.content, &proof_bytes.signature, public_key) {
//         Ok(proof_input)
//     } else {
//         println!("invalid sig");
//         Err(OneOf::new(InvalidProof {}))
//     }
// }

pub struct ProofAction {
    action: ActionType,
    target: Target,
    target_data: TargetList,
}

impl ProofAction {
    pub fn new(action: ActionType, target: Target, target_data: TargetList) -> Self {
        Self {
            action,
            target,
            target_data,
        }
    }
}

impl<'a, T> ProofContent<'a, T>
where
    T: ByteSerial,
{
    fn new(
        expires: u64,
        action: ProofAction,
        ephemeral: &'a BytePacked<Ephemeral<()>>,
        data: &'a BytePacked<T>,
    ) -> Self {
        Self {
            action: action.action,
            target: action.target,
            target_data: action.target_data,
            expires,
            ephemeral,
            data,
        }
    }

    // pub fn verify<F>(&self, time: u64, signature: &[u8], public_key: &PublicKey, used: F) -> Result<(), InvalidProof>
    //     where F: FnOnce(&Ephemeral<()>) -> Result<(), InvalidProof>
    // {
    //     // if verify.verify(&proof_input.about, application).is_err() {
    //     //     println!("bad action");
    //     //     return Err(OneOf::new(InvalidProof {}));
    //     // }

    //     if time >= self.expires + LEEWAY {
    //         eprintln!("expired proof");
    //         return Err(InvalidProof);
    //     };

    // }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        rmp::encode::write_array_len(&mut buf, 6).unwrap();
        rmp::encode::write_str(&mut buf, self.action.name()).unwrap();
        rmp::encode::write_str(&mut buf, self.target.name()).unwrap();
        rmp::encode::write_array_len(&mut buf, self.target_data.0.len() as u32).unwrap();
        for t in &self.target_data.0 {
            rmp::encode::write_str(&mut buf, t).unwrap();
        }
        rmp::encode::write_u64(&mut buf, self.expires).unwrap();
        rmp::encode::write_bin(&mut buf, self.ephemeral.as_bytes()).unwrap();
        rmp::encode::write_bin(&mut buf, self.data.as_bytes()).unwrap();

        buf
    }

    pub fn deserialize(bytes: &'a [u8]) -> Result<Self, InvalidProof> {
        // let mut cursor = Cursor::new(bytes);
        let mut cursor = Cursor::new(bytes);
        let array_len = rmp::decode::read_array_len(&mut cursor).map_err(|_| InvalidProof {})?;
        if array_len != 6 {
            return Err(InvalidProof);
        }
        let action = rmp_read_str(bytes, &mut cursor).map_err(|_| InvalidProof {})?;
        let action = ActionType::from_name(action)?;
        let target = rmp_read_str(bytes, &mut cursor).map_err(|_| InvalidProof {})?;
        let target = Target::from_name(target)?;

        let array_len = rmp::decode::read_array_len(&mut cursor).map_err(|_| InvalidProof {})?;
        let mut targets = Vec::with_capacity(array_len as usize);
        for _ in 0..array_len {
            let target = rmp_read_str(bytes, &mut cursor).map_err(|_| InvalidProof {})?;
            targets.push(target.to_owned())
        }
        let expires = rmp::decode::read_u64(&mut cursor).map_err(|_| InvalidProof {})?;
        let ephemeral = rmp_read_bin(bytes, &mut cursor).map_err(|_| InvalidProof {})?;
        let data = rmp_read_bin(bytes, &mut cursor).map_err(|_| InvalidProof {})?;
        let data = BytePacked::new(data);

        Ok(Self {
            action,
            target,
            target_data: TargetList(targets),
            expires,
            ephemeral: BytePacked::new(ephemeral),
            data,
        })
    }
}

#[derive(Debug)]
pub struct TargetList(Vec<String>);

impl TargetList {
    pub fn new<S: AsRef<str>>(vec: Vec<S>) -> Self {
        Self(vec.into_iter().map(|s| s.as_ref().to_owned()).collect())
    }

    pub fn user(user_id: &str) -> Self {
        Self::new(vec![user_id])
    }

    pub fn from_vec(vec: Vec<String>) -> Self {
        Self(vec)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn as_vec(self) -> Vec<String> {
        self.0
    }
}

// pub struct AboutVerify {
//     allowed_actions: Vec<ActionType>,
// }

// impl AboutVerify {
//     pub fn action(action: ActionType) -> Self {
//         Self {
//             allowed_actions: vec![action],
//         }
//     }

//     pub fn with_allowed(allowed_actions: Vec<ActionType>) -> Self {
//         Self {
//             allowed_actions,
//         }
//     }

//     // pub fn with_claims_actions(application: &str) -> Self {
//     //     Self::with_allowed(
//     //         application,
//     //         vec![
//     //             ActionType::Reset,
//     //             ActionType::Merge,
//     //             ActionType::Add,
//     //             ActionType::Delete,
//     //         ],
//     //     )
//     // }

//     // pub fn verify(&self, about: &ProofAbout, application: &str) -> Result<(), InvalidProof> {
//     //     if !self.allowed_actions.contains(&about.action) || application != about.application {
//     //         return Err(InvalidProof {});
//     //     }

//     //     Ok(())
//     // }
// }

#[derive(Debug)]
/// A proof is issued by the application using their private key and verified using the public key stored inside `tiauth`.
pub struct Proof<T> {
    phantom: PhantomData<T>,
    content: Vec<u8>,
    signature: Vec<u8>,
}

impl<T: ByteSerial> Proof<T> {
    pub fn create(
        key: &Key,
        expires: u64,
        action: ProofAction,
        ephemeral: &BytePacked<Ephemeral<()>>,
        data: &BytePacked<T>,
    ) -> Self {
        let proof_content = ProofContent::new(expires, action, ephemeral, data);

        let content = proof_content.serialize();

        let signature = sign_data(key, &content);

        Self {
            content,
            signature,
            phantom: PhantomData,
        }
    }

    // pub fn verify<F>(&self, time: u64, signature: &[u8], public_key: &PublicKey, used: F) -> Result<(), InvalidProof>
    //     where F: FnOnce(&Ephemeral<()>) -> Result<(), InvalidProof>
    // {
    //     // if verify.verify(&proof_input.about, application).is_err() {
    //     //     println!("bad action");
    //     //     return Err(OneOf::new(InvalidProof {}));
    //     // }

    //     if time >= self.expires + LEEWAY {
    //         eprintln!("expired proof");
    //         return Err(InvalidProof);
    //     };
    pub fn verify<'a, F>(
        &'a self,
        public_key: &PublicKey,
        time: u64,
        used: F,
    ) -> Result<UnvalidatedProofObject<'a, T>, InvalidProof>
    where
        F: FnOnce(&EphemeralView<()>) -> Result<(), InvalidProof>,
    {
        let content = ProofContent::<T>::deserialize(&self.content)?;

        if time >= content.expires + LEEWAY {
            return Err(InvalidProof);
        }

        if !verify_signature(&self.content, &self.signature, public_key) {
            eprintln!("invalid sig");
            return Err(InvalidProof);
        }

        let ephemeral = content
            .ephemeral
            .try_deserialize()
            .map_err(|_| InvalidProof)?;
        used(&ephemeral)?;

        Ok(UnvalidatedProofObject {
            action: content.action,
            target: content.target,
            target_data: content.target_data,
            data: content.data,
        })
    }
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

// pub fn create_proof<T: ByteSerial>(
//     expires_in: u64,
//     action: ActionType,
//     target: Target,
//     target_data: TargetList,
//     nonce: impl SerializedAs<Ephemeral<()>>,
//     data: impl SerializedAs<T>,
//     key: &Key,
//     now: u64
// ) -> Proof<T> {
//     let expires = expires_in + now;
//     let content = ProofContent::new(
//         application,
//         expires,
//         action,
//         target,
//         target_data,
//         nonce.serialized(),
//         data.serialized(),
//     );

//     write_proof(&content, key)
// }

// fn write_proof<T: ByteSerial>(proof_content: &ProofContent<T>, key: &Key) -> Proof<T> {
//     let content = proof_content.to_bytes();
//     let signature = sign_data(key, &content);

//     Proof {
//         content,
//         signature,
//         phantom: PhantomData,
//     }
// }

#[derive(Debug, PartialEq)]
pub struct Session {
    encrypted: Vec<u8>,
}

impl Encodable for Session {
    type Error = InvalidSession;

    fn decode(encoded: &str) -> Result<Self, Self::Error>
    where
        Self: Sized {
        let encrypted = b64::URL_SAFE_NO_PAD.decode(encoded).map_err(|_| InvalidSession)?;

        Ok(Self {
            encrypted
        })
    }

    fn encode(&self) -> String {
        b64::URL_SAFE_NO_PAD.encode(&self.encrypted)
    }
}

trait SessionVerifyStatus {
    type StatusVerifyError;

    fn encrypted_bytes(&self) -> &[u8];

    fn decrypt(&self, keys: &[SessionKey]) -> Result<DecryptedSession, InvalidSession> {
        let decrypted = crypto::symmetric_decrypt(self.encrypted_bytes(), keys)
            .map_err(|_e| InvalidSession {})?;

        Ok(DecryptedSession { decrypted })
    }
}

impl Session {
    pub fn create(
        user_id: &str,
        expires_in: u64,
        pw_file_hash: PasswordFileHash,
        session_claims: impl SerializedAs<Claims>,
        key: &SessionKey,
        time: u64,
    ) -> Self {
        let expires = expires_in + time;
        let content = SessionContent::new(
            user_id,
            time,
            expires,
            pw_file_hash,
            session_claims.serialized(),
        );

        Self {
            encrypted: crypto::symmetric_encrypt(
                &content.to_bytes(),
                key,
                &mut StdRng::from_entropy(),
            ),
        }
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.encrypted
    }

    pub fn decrypt<E, F, FE>(
        &self,
        time: u64,
        keys: &[SessionKey],
        status: F,
        convert: FE,
    ) -> Result<DecryptedSession, E>
    where
        E: std::fmt::Debug,
        FE: Fn(InvalidSession) -> E,
        F: FnOnce(&Self) -> Result<SessionStatus, E>,
    {
        let status = status(&self)?;

        status.valid(time).map_err(|e| convert(e))?;

        let decrypted = crypto::symmetric_decrypt(&self.encrypted, keys)
            .map_err(|_| convert(InvalidSession))?;

        Ok(DecryptedSession { decrypted })
    }
}

pub struct DecryptedSession {
    decrypted: Vec<u8>,
}

impl DecryptedSession {
    /// Note that the Session has not yet been verified, it might be expired or revoked!
    pub fn read(&self) -> SessionContent {
        SessionContent::from_bytes(&self.decrypted)
    }
}

#[derive(Error, Debug)]
#[error("Invalid session.")]
pub struct InvalidSession;

// pub fn verify_session_bytes(
//     session_encrypted: &Session,
//     keys: &[SessionKey],
// ) -> Result<VerifiedSession, InvalidSession> {
//     let session_decrypted = crypto::symmetric_decrypt(&session_encrypted.encrypted_bytes, keys)
//         .map_err(|_e| InvalidSession {})?;

//     Ok(VerifiedSession(session_decrypted))
// }

pub struct EphemeralKey(SymmetricKey);

impl AsSymmetricKey for EphemeralKey {
    fn as_symmetric_key(&self) -> &SymmetricKey {
        &self.0
    }
}

impl EphemeralKey {
    pub fn compute<const INTERVAL: u64>(base_secret: [u8; 32], now: u64, ref_time: u64) -> Self {
        let passed = now - ref_time;

        let intervals_passed = passed / INTERVAL;

        let symmetric_key = SymmetricKey::derive_key(base_secret, intervals_passed);

        Self(symmetric_key)
    }

    pub fn last<const INTERVAL: u64>(
        base_secret: [u8; 32],
        now: u64,
        ref_time: u64,
        amount_valid: u32,
    ) -> Vec<Self> {
        let key_amount = (amount_valid as u64).min((now - ref_time) / INTERVAL + 1);

        (0..(key_amount))
            .rev()
            .map(|i| Self::compute::<INTERVAL>(base_secret, now - (i * INTERVAL), ref_time))
            .collect()
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum EphemeralType {
    NewUser,
    ChangePassword,
    SetPassword,
    Login,
    ProofToken,
}

#[derive(Error, Debug)]
#[error("Invalid EphemeralType.")]
pub struct InvalidEphemeral;

pub trait EphemeralStateType {
    type VerifyType<'a>;

    fn valid_type(eph_type: &EphemeralType) -> Result<(), InvalidEphemeral> {
        if !Self::is_valid_type(eph_type) {
            return Err(InvalidEphemeral);
        }

        Ok(())
    }

    fn is_valid_type(eph_type: &EphemeralType) -> bool;

    /// Return the state in a form that is necessary for the comparison. This can also be bytes.
    fn get_state<'a>(state: &'a [u8]) -> Self::VerifyType<'a>;

    /// Create a binary representation of the state that should be compared when verifying the Ephemeral.
    fn create_state(self) -> impl AsRef<[u8]>;
}

pub struct EphemeralLoginState {
    pub count: u64,
    pub expires: u64,
    pub password_file: String,
}

pub struct EphemeralProofTokenState {
    pub count: u64,
    pub expires: u64,
}

pub struct EphemeralChangePasswordState {
    pub password_file: String,
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

#[derive(PartialEq, Debug)]
pub struct PasswordFileHash([u8; 32]);

impl PasswordFileHash {
    pub fn create(password_file: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password_file.as_bytes());
        Self(hasher.finalize().into())
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 32);
        Self(bytes.try_into().unwrap())
    }
}

impl EphemeralStateType for EphemeralLoginState {
    fn is_valid_type(eph_type: &EphemeralType) -> bool {
        eph_type == &EphemeralType::Login
    }

    /// This function panics if the state is not the correct elngth
    fn get_state(state: &[u8]) -> Self::VerifyType<'_> {
        assert!(state.len() >= 16);
        let counter_bytes: [u8; 8] = state[0..8].try_into().unwrap();
        let expires_bytes: [u8; 8] = state[8..16].try_into().unwrap();
        let pw_file_hash_bytes = &state[16..];

        (
            u64::from_le_bytes(counter_bytes),
            u64::from_le_bytes(expires_bytes),
            PasswordFileHash::from_bytes(pw_file_hash_bytes),
        )
    }

    fn create_state(self) -> impl AsRef<[u8]> {
        let mut state_bytes = [0u8; 48];

        state_bytes[0..8].copy_from_slice(&self.count.to_le_bytes());
        state_bytes[8..16].copy_from_slice(&self.expires.to_le_bytes());

        let pw_file_hash = PasswordFileHash::create(&self.password_file);
        state_bytes[16..].copy_from_slice(pw_file_hash.as_bytes());

        state_bytes
    }

    type VerifyType<'a> = (u64, u64, PasswordFileHash);
}

impl EphemeralStateType for EphemeralProofTokenState {
    fn is_valid_type(eph_type: &EphemeralType) -> bool {
        eph_type == &EphemeralType::ProofToken
    }

    /// This function panics if the state is not exactly 16 bytes.
    fn get_state(state: &[u8]) -> Self {
        assert_eq!(state.len(), 16);
        let counter_bytes: [u8; 8] = state[0..8].try_into().unwrap();
        let expires_bytes: [u8; 8] = state[8..16].try_into().unwrap();

        Self {
            count: u64::from_le_bytes(counter_bytes),
            expires: u64::from_le_bytes(expires_bytes),
        }
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

    fn try_get_state<'a, S: EphemeralStateType>(
        &self,
        state: &'a [u8],
    ) -> Result<S::VerifyType<'a>, InvalidEphemeral> {
        S::valid_type(&self)?;

        Ok(S::get_state(state))
    }

    fn key_name(&self) -> &'static str {
        match self {
            Self::NewUser => "new_user",
            Self::ChangePassword => "change_pass",
            Self::SetPassword => "set_pass",
            Self::Login => "login",
            Self::ProofToken => "proof_token",
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
    encrypted: Vec<u8>,
}

pub struct EphemeralView<'a, T: ByteSerial> {
    encrypted: &'a [u8],
    phantom: PhantomData<T>,
}

impl<'a, T: ByteSerial> EphemeralView<'a, T> {
    pub fn decrypt(
        &self,
        keys: &[EphemeralKey],
    ) -> Result<DecryptedEphemeral<T>, InvalidEphemeral> {
        Ephemeral::decrypt_bytes(&self.encrypted, keys)
        // let Self { encrypted, .. } = self;

        // Ephemeral::verify_components(encrypted, verify_keys, application)
    }
}

impl<T: ByteSerial + 'static> ByteSerial for Ephemeral<T> {
    type Deserialized<'a> = EphemeralView<'a, T>;

    type DeserializeErr = InvalidEphemeral;

    fn serialize(&self) -> crate::ByteOwned<Self>
    where
        Self: Sized,
    {
        // let mut bytes = self.content.clone();
        // bytes.extend_from_slice(&self.tag);
        ByteOwned::new(self.encrypted.clone())
    }

    fn try_deserialize(bytes: &[u8]) -> Result<Self::Deserialized<'_>, Self::DeserializeErr> {
        // if bytes.len() < 32 {
        //     return Err(InvalidEphemeral)
        // }

        // let (content, tag) = bytes.split_at(bytes.len()-32);
        // let tag: &[u8; 32] = tag.try_into().unwrap();

        Ok(Self::Deserialized {
            phantom: PhantomData,
            encrypted: bytes,
        })
    }

    fn try_deserialize_owned(bytes: &[u8]) -> Result<Self, Self::DeserializeErr>
    where
        Self: Sized,
    {
        // if bytes.len() < 32 {
        //     return Err(InvalidEphemeral)
        // }

        // let (content, tag) = bytes.split_at(bytes.len()-32);
        // let tag: [u8; 32] = tag.try_into().unwrap();

        Ok(Self {
            phantom: PhantomData,
            encrypted: bytes.to_vec(),
        })
    }
}

impl<T: ByteSerial> Encodable for Ephemeral<T> {
    type Error = InvalidEphemeral;

    fn decode(encoded: &str) -> Result<Self, Self::Error> {
        let bytes = match b64::URL_SAFE_NO_PAD.decode(encoded) {
            Ok(bytes) => bytes,
            Err(_) => {
                println!("invalid decode");
                return Err(InvalidEphemeral);
            }
        };
        // let total_len = bytes.len();
        // if total_len < 4 {
        //     println!("shorter than 4 bytes, no content length.");
        //     return Err(InvalidEphemeral);
        // }
        // let ln = &bytes[(total_len - 4)..total_len];
        // let content_length = u32::from_le_bytes([ln[0], ln[1], ln[2], ln[3]]) as usize;
        // if total_len < 4 + 32 + content_length {
        //     println!("Not long enough for content and valid tag.");
        //     return Err(InvalidEphemeral);
        // }
        // // After this the original contains only the content
        // let tag_vec = bytes.split_off(content_length);
        // if tag_vec.len() + 4 != 36 {
        //     println!("Incorrect length for content length and tag.");
        //     return Err(InvalidEphemeral);
        // }
        // let tag: [u8; 32] = (&tag_vec[0..32]).try_into().unwrap();

        Ok(Self {
            phantom: PhantomData,
            encrypted: bytes,
        })
    }

    fn encode(&self) -> String {
        b64::URL_SAFE_NO_PAD.encode(&self.encrypted)
        // let content_length: [u8; 4] = (self.content.len() as u32).to_le_bytes();
        // let total_len = content_length.len() + self.content.len() + self.tag.len();

        // combine_encode(
        //     &[&self.content, &self.tag, &content_length],
        //     total_len,
        // )
    }
}

impl<T: ByteSerial> Ephemeral<T> {
    pub fn create_expires<S: EphemeralStateType>(
        key: &EphemeralKey,
        user_id: &str,
        state: S,
        eph_type: EphemeralType,
        expires: u64,
        data: &BytePacked<T>,
    ) -> Self {
        assert!(S::is_valid_type(&eph_type));
        let state = state.create_state();
        let ephemeral = EphemeralContent {
            user_id,
            expires,
            state: state.as_ref(),
            eph_type,
            data,
        };

        let serialized = ephemeral.serialize();

        let encrypted = crypto::symmetric_encrypt(&serialized, key, &mut StdRng::from_entropy());

        Self {
            phantom: PhantomData,
            encrypted,
        }
    }

    pub fn create<S: EphemeralStateType>(
        key: &EphemeralKey,
        user_id: &str,
        state: S,
        eph_type: EphemeralType,
        time: u64,
        data: &BytePacked<T>,
    ) -> Self {
        // By default validity as long as EphemeralKey, so it's actually bounded by the key in this case
        let expires = time + (EPHEMERAL_INTERVAL * 2);
        Self::create_expires(key, user_id, state, eph_type, expires, data)
    }

    // fn verify_components<'a, 'tag>(
    //     encrypted: &'a [u8],
    //     verify_keys: &[EphemeralKey],
    //     application: &str,
    // ) -> Result<EphemeralContent<'a, T>, InvalidEphemeral> {
    //     crypto::symmetric_decrypt(content, verify_keys, tag).map_err(|_| InvalidEphemeral)?;

    //     let content = EphemeralContent::deserialize(content)?;

    //     if content.application != application {
    //         return Err(InvalidEphemeral);
    //     }

    //     Ok(content)
    // }

    fn decrypt_bytes(
        bytes: &[u8],
        keys: &[EphemeralKey],
    ) -> Result<DecryptedEphemeral<T>, InvalidEphemeral> {
        let decrypted = crypto::symmetric_decrypt(bytes, keys).map_err(|_| InvalidEphemeral)?;

        Ok(DecryptedEphemeral {
            decrypted,
            phantom: PhantomData,
        })
    }

    pub fn decrypt(
        &self,
        keys: &[EphemeralKey],
    ) -> Result<DecryptedEphemeral<T>, InvalidEphemeral> {
        Self::decrypt_bytes(&self.encrypted, keys)
    }

    // Checks if the content of the Ephemeral was indeed created using one of the verify keys. It does not check for re-use.
    // pub fn verify<'a>(
    //     &'a self,
    //     verify_keys: &[EphemeralKey],
    //     application: &str,
    // ) -> Result<EphemeralContent<'a, T>, InvalidEphemeral> {
    //     let Self { tag, content, .. } = &self;

    //     Self::verify_components(tag, content, verify_keys, application)
    // }
}

pub struct DecryptedEphemeral<T> {
    decrypted: Vec<u8>,
    phantom: PhantomData<T>,
}

impl<T: ByteSerial> DecryptedEphemeral<T> {
    pub fn read<'a>(&'a self) -> EphemeralContent<'a, T> {
        // Since it's encrypted, we know the structure must be correct so we just unwrap here
        EphemeralContent::deserialize(&self.decrypted).unwrap()
    }
}

#[derive(Debug)]
pub struct EphemeralContent<'a, T: ByteSerial> {
    /// Allowed to be empty for ProofToken
    pub user_id: &'a str,
    expires: u64,
    // Note that we do not need an application here because keys are application-specific
    /// This can be used for the either the state itself or a hash of the state (based on the EphemeralType), the Ephemeral is only
    /// valid if the state is unchanged from when the Ephemeral was handed out
    state: &'a [u8],
    pub eph_type: EphemeralType,
    /// Access to the data is only given after verifying the content
    data: &'a BytePacked<T>,
}

// struct EphemeralVerify<'a> {
//     eph_type: EphemeralType,

// }

impl<'a, T: ByteSerial> EphemeralContent<'a, T> {
    // fn new(
    //     user_id: &'a str,
    //     state: &'a [u8],
    //     eph_type: EphemeralType,
    //     data: &'a BytePacked<T>,
    // ) -> Self {
    //     Self {
    //         user_id,
    //         state,
    //         eph_type,
    //         data,
    //     }
    // }

    pub fn verify_state<
        S: EphemeralStateType,
        F: FnOnce(S::VerifyType<'a>) -> Result<(), InvalidEphemeral>,
    >(
        &self,
        time: u64,
        verify: F,
    ) -> Result<T::Deserialized<'a>, InvalidEphemeral> {
        if time >= self.expires + LEEWAY {
            return Err(InvalidEphemeral);
        }

        // This also checks if the eph_type is valid
        let s: S::VerifyType<'a> = self.eph_type.try_get_state::<S>(&self.state)?;

        verify(s)?;

        Ok(self.data.deserialize())
    }

    pub fn verify_state_equal<S: EphemeralStateType>(
        &self,
        time: u64,
        current_state_input: S,
    ) -> Result<T::Deserialized<'a>, InvalidEphemeral> {
        if time >= self.expires + LEEWAY {
            return Err(InvalidEphemeral);
        }

        S::valid_type(&self.eph_type)?;

        let current_state = current_state_input.create_state();

        if current_state.as_ref() != self.state {
            return Err(InvalidEphemeral);
        }

        Ok(self.data.deserialize())
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        rmp::encode::write_array_len(&mut buf, 5).unwrap();
        rmp::encode::write_str(&mut buf, self.user_id).unwrap();
        rmp::encode::write_u64(&mut buf, self.expires).unwrap();
        rmp::encode::write_bin(&mut buf, self.state).unwrap();
        let eph_type = self.eph_type.key_name();
        rmp::encode::write_str(&mut buf, eph_type).unwrap();
        let data_bytes = self.data.as_bytes();
        rmp::encode::write_bin(&mut buf, data_bytes).unwrap();

        buf
    }

    fn deserialize(bytes: &'a [u8]) -> Result<Self, InvalidEphemeral> {
        let mut cursor = Cursor::new(bytes);

        let len = rmp::decode::read_array_len(&mut cursor).map_err(|_| InvalidEphemeral)?;
        if len != 5 {
            return Err(InvalidEphemeral);
        }
        let user_id = rmp_read_str(bytes, &mut cursor).map_err(|_| InvalidEphemeral)?;
        let expires = rmp::decode::read_u64(&mut cursor).map_err(|_| InvalidEphemeral)?;
        let state = rmp_read_bin(bytes, &mut cursor).map_err(|_| InvalidEphemeral)?;
        let eph_type = rmp_read_str(bytes, &mut cursor).unwrap();
        let eph_type = EphemeralType::from_key_name(eph_type).map_err(|_| InvalidEphemeral)?;
        let data = rmp_read_bin(bytes, &mut cursor).map_err(|_| InvalidEphemeral)?;
        let data: &BytePacked<T> = BytePacked::new(data);
        Ok(Self {
            user_id,
            expires,
            state,
            eph_type,
            data,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct SessionContent<'a> {
    pub user_id: String,
    issued: u64,
    expires: u64,
    pw_file_hash: PasswordFileHash,
    /// These are a subset of the "login claims"
    session_claims: &'a BytePacked<Claims>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionCreate<'a> {
    user_id: &'a str,
    issued: u64,
    expires: u64,
}

impl<'a> SessionContent<'a> {
    pub fn new(
        user_id: &str,
        issued: u64,
        expires: u64,
        pw_file_hash: PasswordFileHash,
        session_claims: &'a BytePacked<Claims>,
    ) -> Self {
        Self {
            user_id: user_id.to_owned(),
            issued,
            expires,
            pw_file_hash,
            session_claims,
        }
    }

    pub fn verify(
        &self,
        time: u64,
        password_file: &str,
    ) -> Result<&BytePacked<Claims>, InvalidSession> {
        let pw_file_hash = PasswordFileHash::create(password_file);

        if self.pw_file_hash != pw_file_hash {
            return Err(InvalidSession);
        }

        if time >= self.expires + LEEWAY {
            return Err(InvalidSession);
        }

        Ok(&self.session_claims)
    }

    pub fn verify_max_age(
        &self,
        time: u64,
        password_file: &str,
        max_age: u64,
    ) -> Result<&BytePacked<Claims>, InvalidSession> {
        if time > self.issued + max_age {
            return Err(InvalidSession);
        }

        self.verify(time, password_file)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let about = SessionCreate {
            user_id: &self.user_id,
            issued: self.issued,
            expires: self.expires,
        };
        let about_bytes = rmp_serde::encode::to_vec(&about).unwrap();
        rmp::encode::write_bin(&mut buf, &about_bytes).unwrap();
        rmp::encode::write_bin(&mut buf, &self.pw_file_hash.as_bytes()).unwrap();
        rmp::encode::write_bin(&mut buf, self.session_claims.as_bytes()).unwrap();

        buf
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        // let mut cursor = Cursor::new(bytes);
        let mut cursor = Cursor::new(bytes);

        let len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let about = cursor_slice(bytes, &mut cursor, len);

        let pw_file_hash = rmp_read_bin(bytes, &mut cursor).unwrap();

        let len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let claims = cursor_slice(bytes, &mut cursor, len);

        let about: SessionCreate = rmp_serde::from_slice(about).unwrap();

        Self {
            user_id: about.user_id.to_owned(),
            issued: about.issued,
            expires: about.expires,
            pw_file_hash: PasswordFileHash::from_bytes(pw_file_hash),
            session_claims: BytePacked::new(claims),
        }
    }
}
