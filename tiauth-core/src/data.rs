#![allow(dead_code)]

use crate::crypto::{load_public_key, PublicKey, SavedPublicKey};
use crate::util::{cursor_slice, nonce_384_bytes};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::io::Cursor;
use std::marker::PhantomData;
use std::ops::Range;
use std::str;
use terrors::OneOf;
use thiserror::Error;

use zerovec::vecs::Index32;
use zerovec::VarZeroVec;

#[derive(Debug, PartialEq)]
struct ClaimsBytes(ByteBuf);

#[derive(Debug, PartialEq)]
pub struct Login<'a> {
    pub user_id: String,
    pub password_file: String,
    pub claims: &'a BytePacked<Claims>,
}

#[derive(Debug, PartialEq)]
pub struct LoginPassword {
    pub user_id: String,
    pub password_file: String,
}

fn deserialize_login_password(bytes: &[u8], cursor: &mut Cursor<&[u8]>) -> LoginPassword {
    let user_id_len = rmp::decode::read_str_len(cursor).unwrap();
    let user_id_bytes = cursor_slice(bytes, cursor, user_id_len);
    let user_id = std::str::from_utf8(user_id_bytes).unwrap().to_owned();

    let pw_len = rmp::decode::read_str_len(cursor).unwrap();
    let pw_bytes = cursor_slice(bytes, cursor, pw_len);
    let password_file = std::str::from_utf8(pw_bytes).unwrap().to_owned();

    LoginPassword {
        user_id,
        password_file,
    }
}

impl LoginPassword {
    pub fn deserialize_from_login(bytes: &[u8]) -> Self {
        let mut cursor = Cursor::new(bytes);
        deserialize_login_password(bytes, &mut cursor)
    }
}

impl<'a> Login<'a> {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        rmp::encode::write_str(&mut buf, &self.user_id).unwrap();
        rmp::encode::write_str(&mut buf, &self.password_file).unwrap();
        rmp::encode::write_bin(&mut buf, self.claims.as_bytes()).unwrap();

        buf
    }

    pub fn deserialize(bytes: &'a [u8]) -> Self {
        let mut cursor = Cursor::new(bytes);

        let LoginPassword {
            user_id,
            password_file,
        } = deserialize_login_password(bytes, &mut cursor);

        let claims_len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let claims_bytes = cursor_slice(bytes, &mut cursor, claims_len);

        Self {
            user_id,
            password_file,
            claims: BytePacked::new(claims_bytes),
        }
    }
}

impl<T> ToOwned for BytePacked<T>
where
    T: ByteSerial,
{
    type Owned = ByteOwned<T>;

    fn to_owned(&self) -> Self::Owned {
        ByteOwned {
            phantom: PhantomData,
            bytes: self.bytes.to_vec(),
        }
    }
}

#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct BytePacked<T>
where
    T: ByteSerial,
{
    phantom: PhantomData<T>,
    bytes: [u8],
}

#[derive(Debug, PartialEq)]
pub struct ByteOwned<T>
where
    T: ByteSerial,
{
    bytes: Vec<u8>,
    phantom: PhantomData<T>,
}

impl<T> ByteOwned<T>
where
    T: ByteSerial,
{
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            phantom: PhantomData,
        }
    }

    pub fn as_packed(&self) -> &BytePacked<T> {
        <Self as Borrow<_>>::borrow(self)
    }
}

impl<T> Borrow<BytePacked<T>> for ByteOwned<T>
where
    T: ByteSerial,
{
    fn borrow(&self) -> &BytePacked<T> {
        BytePacked::new(&self.bytes)
    }
}

impl<T: ByteSerial> From<Vec<u8>> for ByteOwned<T> {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            phantom: PhantomData,
        }
    }
}

// pub trait BytePackable {
//     fn to_bytes(&self) -> &[u8];

//     fn to_packed<'a>(&'a self) -> BytePacked<'a, Self> where Self: Sized {
//         BytePacked::new(&self.to_bytes())
//     }
// }

impl<T> BytePacked<T>
where
    T: ByteSerial,
{
    pub fn new(bytes: &[u8]) -> &Self {
        //unsafe { mem::transmute(&*bytes) }
        unsafe { &*(bytes as *const [u8] as *const BytePacked<T>) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn empty() -> &'static Self {
        Self::new(&[])
    }

    pub fn deserialize(&self) -> T::Deserialized<'_> {
        T::deserialize(&self.bytes)
    }

    pub fn deserialize_owned(&self) -> T {
        T::deserialize_owned(&self.bytes)
    }
}

pub trait ByteSerial {
    type Deserialized<'a>
    where
        Self: 'a;
    fn serialize(&self) -> ByteOwned<Self>
    where
        Self: Sized;

    fn deserialize(bytes: &[u8]) -> Self::Deserialized<'_>;

    fn deserialize_owned(bytes: &[u8]) -> Self;
}

pub trait SerializedAs<T>
where
    T: ByteSerial,
{
    fn serialized(&self) -> &BytePacked<T>;
}

impl<T> SerializedAs<T> for ByteOwned<T>
where
    T: ByteSerial,
{
    fn serialized(&self) -> &BytePacked<T> {
        self.as_packed()
    }
}

impl<T> SerializedAs<T> for &BytePacked<T>
where
    T: ByteSerial,
{
    fn serialized(&self) -> &BytePacked<T> {
        self
    }
}

impl ByteSerial for () {
    type Deserialized<'a> = ();

    fn serialize(&self) -> ByteOwned<Self> {
        ByteOwned::new(Vec::with_capacity(0))
    }

    fn deserialize(bytes: &[u8]) -> Self::Deserialized<'_> {
        if bytes.is_empty() {
        } else {
            panic!("Only empty bytes can be deserialized as ()")
        }
    }

    fn deserialize_owned(bytes: &[u8]) -> Self {
        <Self as ByteSerial>::deserialize(bytes)
    }
}

/// VarZeroVec require a "serialization" step to create and pushing to them is expensive, so it is preferred to treat them as immutable and create them only
/// when needed from a Claims struct.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimsView<'a> {
    #[serde(borrow)]
    keys: VarZeroVec<'a, str, Index32>,
    #[serde(borrow)]
    values: VarZeroVec<'a, [u8], Index32>,
}

#[derive(Debug, PartialEq)]
pub struct Claims {
    keys: Vec<String>,
    values: Vec<Vec<u8>>,
}

impl ByteSerial for Claims {
    type Deserialized<'a> = ClaimsView<'a>;

    fn serialize(&self) -> ByteOwned<Self> {
        let view = self.to_view();

        ByteOwned::new(rmp_serde::to_vec(&view).unwrap())
    }

    fn deserialize(bytes: &[u8]) -> ClaimsView {
        let view: ClaimsView = rmp_serde::from_slice(bytes).unwrap();

        view
    }

    /// Note that this is quite expensive, as it has to iterate and clone the data. You probably don't want to use this.
    fn deserialize_owned(bytes: &[u8]) -> Self {
        let view = <Self as ByteSerial>::deserialize(bytes);
        let keys = view.keys.iter().map(|t| t.to_owned()).collect();
        let values = view.values.iter().map(|t| t.to_vec()).collect();
        Self { keys, values }
    }
}

impl Claims {
    /// This is a convenience function. It assumes the input vector is unsorted and hence performs sorting itself. Use [Self::from_keys_values] if they are already sorted.
    pub fn new<S, V>(map: Vec<(S, V)>) -> Self
    where
        S: Into<String>,
        V: AsRef<[u8]>,
    {
        let mut map: Vec<(String, Vec<u8>)> = map
            .into_iter()
            .map(|(s, v)| (s.into(), v.as_ref().to_vec()))
            .collect();

        map.sort_by_cached_key(|(k, _v)| k.clone());

        let (keys, values): (Vec<String>, Vec<Vec<u8>>) = map.into_iter().unzip();

        Self { keys, values }
    }

    pub fn from_keys_values(keys: Vec<String>, values: Vec<Vec<u8>>) -> Self {
        Self {
            keys, values
        }
    }

    pub fn empty() -> Self {
        Self::new::<String, Vec<u8>>(vec![])
    }

    fn to_view(&self) -> ClaimsView {
        let keys: VarZeroVec<str, Index32> = VarZeroVec::from(&self.keys);
        let values: VarZeroVec<[u8], Index32> = VarZeroVec::from(&self.values);

        ClaimsView { keys, values }
    }

    pub fn eq_view(&self, other: &ClaimsView) -> bool {
        self.keys.len() == other.keys.len()
            && self
                .keys
                .iter()
                .enumerate()
                .all(|(i, k)| k == &other.keys[i])
            && self.values.len() == other.values.len()
            && self
                .values
                .iter()
                .enumerate()
                .all(|(i, v)| v == &other.values[i])
    }
}

impl<'a> ClaimsView<'a> {
    // pub fn new<S, V>(map: Vec<(S, V)>) -> Self
    // where
    //     S: Into<String>,
    //     V: AsRef<[u8]>,
    // {
    //     let keys: Vec< = map.into_iter().unzip();
    // }

    /// If k is generally a fraction of n, doing linear search is almost always better. However, when k is a power of n (k = k^C) where C < 1, at some point doing binary search is faster.
    /// For C < 0.6, even for small n binary search is almost just as fast as linear. For larger n though binary search is faster even at far greater k than just k^C.
    /// If using binary search for each item on the original vec, for a subset of size k out of n claims, we would have O(k ln2(n)).
    /// You can be slightly smarter if the subset is sorted, as we can eliminate everything to the left of the value we find as we iterate through the subset. However, in the worst case
    /// this only eliminates 1 at a time, but it's still always better.
    /// Smarter still, you pick the middle element from the subset, allowing you to split the claims in two. Now the left part of the subset can only be in the left part of the claims,
    /// and the right part of the subset only in the right part of the claims. This even allows parallelizing, although in practice the performance improvement is not huge, especially
    /// when there are not a lot of free threads lying around, like for a webserver.
    fn subset_vec<S: AsRef<str>>(&self, subset: &[S]) -> Vec<(String, Vec<u8>)> {
        let mut vec_out = Vec::with_capacity(subset.len());
        let linear_len = self.keys.len() as f32;
        // In practice we have less operations than this, but their complexities depend on the data and are harder to compute
        // We prefer the binary split in most cases
        let ops_binary = linear_len.log2() * (subset.len() as f32) * 0.5;

        if ops_binary > linear_len {
            self.subset_linear(subset, &mut vec_out, |out, (s, v)| {
                out.push((s.to_string(), v.to_vec()));
            });
        } else {
            self.subset_binary_split(subset, &mut vec_out, |out, (s, v)| {
                out.push((s.to_string(), v.to_vec()));
            });
        }

        vec_out
    }

    fn subset_serialize_msgpack<S: AsRef<str>>(&self, subset: &[S]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        rmp::encode::write_map_len(&mut buf, subset.len() as u32).unwrap();

        let linear_len = self.keys.len() as f32;
        // In practice we have less operations than this, but their complexities depend on the data and are harder to compute
        // We prefer the binary split in most cases
        let ops_binary = linear_len.log2() * (subset.len() as f32) * 0.5;

        if ops_binary > linear_len {
            self.subset_linear(subset, &mut buf, |out, (s, v)| {
                rmp::encode::write_str(out, s).unwrap();
                rmp::encode::write_bin(out, v).unwrap();
            });
        } else {
            self.subset_binary_split(subset, &mut buf, |out, (s, v)| {
                rmp::encode::write_str(out, s).unwrap();
                rmp::encode::write_bin(out, v).unwrap();
            });
        }

        buf
    }

    /// This is 4-5x slower than the above, so in the future maybe write specialized custom "varzerovec" that allows more efficient push.
    pub fn subset_serialize<S: AsRef<str>>(&self, subset: &[S]) -> ByteOwned<Claims> {
        let keys: Vec<String> = Vec::with_capacity(self.keys.len());
        let values: Vec<Vec<u8>> = Vec::with_capacity(self.keys.len());

        let mut out = Claims { keys, values };

        let linear_len = self.keys.len() as f32;
        // In practice we have less operations than this, but their complexities depend on the data and are harder to compute
        // We prefer the binary split in most cases
        let ops_binary = linear_len.log2() * (subset.len() as f32) * 0.5;

        if ops_binary > linear_len {
            self.subset_linear(subset, &mut out, |claims, (s, v)| {
                claims.keys.push(s.to_string());
                claims.values.push(v.to_vec());
            });
        } else {
            self.subset_binary_split(subset, &mut out, |claims, (s, v)| {
                claims.keys.push(s.to_string());
                claims.values.push(v.to_vec());
            });
        }

        out.serialize()
    }

    fn subset_linear<F, O, S>(&self, subset: &[S], out: &mut O, action: F)
    where
        F: Fn(&mut O, (&str, &[u8])),
        S: AsRef<str>,
    {
        let subset_len = subset.len();
        assert!(subset_len > 0);
        let mut i = 0;
        let mut current = &subset[i];

        for (k_i, k) in self.keys.iter().enumerate() {
            if current.as_ref() == k {
                action(out, (k, &self.values[k_i]));
                i += 1;
                if i == subset.len() {
                    break;
                } else {
                    current = &subset[i];
                }
            }
        }
    }

    fn subset_binary_split<F, O, S>(&self, subset: &[S], out: &mut O, action: F)
    where
        F: Fn(&mut O, (&str, &[u8])),
        S: AsRef<str>,
    {
        let start = 0;
        let end = self.keys.len();

        let mut queue: Vec<(Range<usize>, &[S])> = vec![(start..end, subset)];
        while let Some((range, subset_slice)) = queue.pop() {
            if subset_slice.is_empty() {
                continue;
            }

            let middle_element_i = subset_slice.len() / 2;
            let middle_element = &subset_slice[middle_element_i];

            if let Ok(rel_k_i) = self
                .keys
                .binary_search_in_range(middle_element.as_ref(), range.clone())
                .unwrap()
            {
                let k_i = rel_k_i + range.start;
                action(out, (middle_element.as_ref(), &self.values[k_i]));

                let left = range.start..k_i;
                let right = k_i + 1..range.end;

                queue.push((left, &subset_slice[0..middle_element_i]));
                queue.push((
                    right,
                    &subset_slice[middle_element_i + 1..subset_slice.len()],
                ));
            } else {
                panic!("All elements in subset must be present!");
            }
        }
    }

    pub fn get_claim(&self, claim_key: &str) -> &[u8] {
        let claim_i = self.keys.binary_search(claim_key).unwrap();
        &self.values[claim_i]
    }
}

// impl Claims {

//     pub fn none() -> Self {
//         Self(HashMap::new())
//     }

//     /// Returns only claims with keys in the provided subset. Consumes the previous claims object.
//     pub fn into_subset<S>(mut self, subset: Vec<S>) -> Self
//     where
//         S: AsRef<str>,
//     {
//         Self(HashMap::from_iter(
//             subset
//                 .iter()
//                 .filter_map(|s| self.0.remove_entry(s.as_ref())),
//         ))
//     }
// }

#[derive(Debug, PartialEq)]
pub struct SessionContent<'a> {
    pub user_id: String,
    pub application: String,
    pub issued: u64,
    pub expires: u64,
    /// These are a subset of the "login claims"
    pub session_claims: &'a BytePacked<Claims>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionCreate<'a> {
    application: &'a str,
    user_id: &'a str,
    issued: u64,
    expires: u64,
}

impl<'a> SessionContent<'a> {
    pub fn new(
        application: &str,
        user_id: &str,
        issued: u64,
        expires: u64,
        session_claims: &'a BytePacked<Claims>,
    ) -> Self {
        Self {
            user_id: user_id.to_owned(),
            application: application.to_owned(),
            issued,
            expires,
            session_claims,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let about = SessionCreate {
            application: &self.application,
            user_id: &self.user_id,
            issued: self.issued,
            expires: self.expires,
        };
        let about_bytes = rmp_serde::encode::to_vec(&about).unwrap();
        rmp::encode::write_bin(&mut buf, &about_bytes).unwrap();
        rmp::encode::write_bin(&mut buf, self.session_claims.as_bytes()).unwrap();

        buf
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        // let mut cursor = Cursor::new(bytes);
        let mut cursor = Cursor::new(bytes);

        let len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let about = cursor_slice(bytes, &mut cursor, len);

        let len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let claims = cursor_slice(bytes, &mut cursor, len);

        let about: SessionCreate = rmp_serde::from_slice(about).unwrap();

        Self {
            user_id: about.user_id.to_owned(),
            application: about.application.to_owned(),
            issued: about.issued,
            expires: about.expires,
            session_claims: BytePacked::new(claims),
        }
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

#[derive(Debug)]
pub struct ProofContent<'a, T>
where
    T: ByteSerial,
{
    pub about: ProofAbout,
    pub nonce: Vec<u8>,
    pub target_data: TargetList,
    pub data: &'a BytePacked<T>,
}

impl<'a, T> ProofContent<'a, T>
where
    T: ByteSerial,
{
    pub fn new(
        application: &str,
        expires: u64,
        action: ActionType,
        target: Target,
        target_data: TargetList,
        data: &'a BytePacked<T>,
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        let about_bytes = rmp_serde::to_vec(&self.about).unwrap();
        rmp::encode::write_bin(&mut buf, &about_bytes).unwrap();
        rmp::encode::write_bin(&mut buf, &self.nonce).unwrap();
        rmp::encode::write_array_len(&mut buf, self.target_data.0.len() as u32).unwrap();
        for t in &self.target_data.0 {
            rmp::encode::write_str(&mut buf, t).unwrap();
        }
        rmp::encode::write_bin(&mut buf, self.data.as_bytes()).unwrap();

        buf
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        // let mut cursor = Cursor::new(bytes);
        let mut cursor = Cursor::new(bytes);

        let len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let about = cursor_slice(bytes, &mut cursor, len);
        let len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let nonce = cursor_slice(bytes, &mut cursor, len);
        let array_len = rmp::decode::read_array_len(&mut cursor).unwrap();
        let mut targets = Vec::new();

        for _ in 0..array_len {
            let str_len = rmp::decode::read_str_len(&mut cursor).unwrap();
            let str_bytes = cursor_slice(bytes, &mut cursor, str_len);
            // TODO make borrowed as well?
            targets.push(std::str::from_utf8(str_bytes).unwrap().to_owned())
        }

        let len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let data = cursor_slice(bytes, &mut cursor, len);
        let data = BytePacked::new(data);

        let about: ProofAbout = rmp_serde::from_slice(about).unwrap();

        Self {
            about,
            nonce: nonce.to_owned(),
            target_data: TargetList(targets),
            data,
        }
    }

    pub fn select_one(&self) -> Result<String, OneOf<(InvalidProof,)>> {
        let targets = &self.target_data;

        match self.about.target {
            Target::Select => {
                if targets.0.len() == 1 {
                    Ok(targets.0[0].clone())
                } else {
                    Err(OneOf::new(InvalidProof {}))
                }
            }
            Target::All => Err(OneOf::new(InvalidProof {})),
        }
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
}

// impl From<Lazy<Vec<String>>> for TargetList {
//     fn from(value: Lazy<Vec<String>>) -> Self {
//         Self(value)
//     }
// }

// impl<T> Proof<T>
// where
//     T: Serialize + core::fmt::Debug,
// {
//     pub fn new(
//         application: &str,
//         expires_in: u64,
//         action: ActionType,
//         target: Target,
//         target_data: TargetList,
//         data: Lazy<T>,
//         key: &Key,
//     ) -> Self {
//         let now = SystemTime::now()
//             .duration_since(SystemTime::UNIX_EPOCH)
//             .unwrap()
//             .as_secs();
//         let expires = expires_in + now;
//         let proof_content =
//             ProofContent::new(application, expires, action, target, target_data.0, data);

//         Self {
//             inner: ProofInner::new(proof_content, key),
//         }
//     }

//     pub fn into_encoded(self) -> String {
//         b64::URL_SAFE_NO_PAD.encode(Lazy::from_inner(self.inner).take_bytes())
//     }

//     // pub fn create_encoded(application: &str, expires: u64, action: ActionType, target: Target, target_data: Lazy<Vec<String>>, data: Lazy<T>, key: &Key) -> String {
//     //     let proof_content = ProofContent::new(application, expires, action, target, target_data, data);
//     //     let inner = ProofInner::new(proof_content, key);

//     //     b64::URL_SAFE_NO_PAD.encode(&Lazy::from_inner(inner).take_bytes())
//     // }

//     pub fn into_parts(self) -> (Lazy<ProofContent<T>>, Vec<u8>) {
//         (self.inner.proof, self.inner.signature)
//     }
// }

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

#[cfg(test)]
mod test {
    use std::time::Instant;

    use rand::{Rng, RngCore};

    use base64::{engine::general_purpose as b64, Engine as _};

    use super::*;

    fn create_claims_subset() -> (Claims, Vec<String>) {
        let start = Instant::now();

        let mut rng = StdRng::from_entropy();
        let mut s = [0u8; 20];

        let r_end: u32 = 150000;
        let sub_size = 400;
        let r: Range<u32> = 0..r_end;
        let mut subset = Vec::with_capacity(sub_size);
        let mut keys_in = Vec::with_capacity(r_end as usize);
        let mut values_in: Vec<Vec<u8>> = Vec::with_capacity(r_end as usize);

        println!(
            "elapsed pre: {} ms",
            start.elapsed().as_secs_f32() * 1000f32
        );

        for i in r {
            // let snow = Instant::now();
            //println!("elapsed 1: {} ms", snow.elapsed().as_secs_f32()*1000f32);
            rng.fill_bytes(&mut s);
            //println!("elapsed 2: {} ms", snow.elapsed().as_secs_f32()*1000f32);
            let s_str = b64::URL_SAFE_NO_PAD.encode(s);
            //println!("elapsed 3: {} ms", snow.elapsed().as_secs_f32()*1000f32);
            let mut val = i.to_le_bytes().to_vec();
            val.extend(s_str.as_bytes());
            keys_in.push(s_str);
            //println!("elapsed 4: {} ms", snow.elapsed().as_secs_f32()*1000f32);

            //println!("elapsed 5: {} ms", snow.elapsed().as_secs_f32()*1000f32);
            values_in.push(val.to_vec());
            //println!("elapsed 6: {} ms", snow.elapsed().as_secs_f32()*1000f32);
        }
        println!(
            "elapsed fill: {} ms",
            start.elapsed().as_secs_f32() * 1000f32
        );

        keys_in.sort_unstable();

        println!(
            "elapsed sort: {} ms",
            start.elapsed().as_secs_f32() * 1000f32
        );

        for k in &keys_in {
            let f: f32 = rng.gen();
            //keys.push(&k);
            if f < (sub_size as f32 / r_end as f32 * 1.1) {
                subset.push(k.clone());
            }
        }
        println!(
            "elapsed keys: {} ms",
            start.elapsed().as_secs_f32() * 1000f32
        );

        println!("k={}, n={}", subset.len(), values_in.len());

        println!(
            "elapsed conv: {} ms",
            start.elapsed().as_secs_f32() * 1000f32
        );

        let claims = Claims {
            keys: keys_in,
            values: values_in,
        };

        (claims, subset)
    }

    #[test]
    fn test_subset_out() {
        let (claims, subset) = create_claims_subset();
        let serial = claims.serialize();
        println!("size: {} kB.", (serial.bytes.len() as f32) / 1000f32);
        let claims = claims.to_view();

        let t = Instant::now();
        let mut s1 = claims.subset_vec(&subset);
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32() * 1000f32);
        assert_eq!(s1.len(), subset.len());
        s1.sort();

        let t = Instant::now();
        let _ = claims.subset_serialize(&subset);
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32() * 1000f32);

        let t = Instant::now();
        let _ = claims.subset_serialize_msgpack(&subset);
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32() * 1000f32);
    }

    #[test]
    fn test_subset() {
        let (claims, subset) = create_claims_subset();
        let claims = claims.to_view();

        let mut s1: Vec<(String, Vec<u8>)> = Vec::with_capacity(subset.len());
        let t = Instant::now();
        claims.subset_linear(&subset, &mut s1, |out, (s, v)| {
            out.push((s.to_string(), v.to_vec()));
        });
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32() * 1000f32);
        assert_eq!(s1.len(), subset.len());
        s1.sort();

        let mut s5: Vec<(String, Vec<u8>)> = Vec::with_capacity(subset.len());
        let t = Instant::now();
        claims.subset_binary_split(&subset, &mut s5, |out, (s, v)| {
            out.push((s.to_string(), v.to_vec()));
        });
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32() * 1000f32);
        assert_eq!(s5.len(), subset.len());
        s5.sort();

        assert_eq!(s1, s5);
    }
}
