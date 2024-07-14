#![allow(dead_code)]

use crate::crypto::{load_public_key, PublicKey, SavedPublicKey};
use crate::util::{cursor_slice, nonce_384_bytes, rmp_read_bin, rmp_read_str};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::borrow::Borrow;
use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt::{Debug, Display};
use std::io::Cursor;
use std::marker::PhantomData;
use std::ops::Range;
use std::str::{self, Utf8Error};
use std::sync::OnceLock;
use terrors::OneOf;
use thiserror::Error;
use zerovec::maps::MutableZeroVecLike;

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
        assert_eq!(rmp::decode::read_array_len(&mut cursor).unwrap(), 3);
        deserialize_login_password(bytes, &mut cursor)
    }

    pub fn into_login(self, claims: &BytePacked<Claims>) -> Login {
        Login {
            user_id: self.user_id,
            password_file: self.password_file,
            claims
        }
    }
}

impl<'a> Login<'a> {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, 3).unwrap();
        rmp::encode::write_str(&mut buf, &self.user_id).unwrap();
        rmp::encode::write_str(&mut buf, &self.password_file).unwrap();
        rmp::encode::write_bin(&mut buf, self.claims.as_bytes()).unwrap();

        buf
    }

    pub fn deserialize_tuple(bytes: &'a [u8]) -> (LoginPassword, &BytePacked<Claims>) {
        let mut cursor = Cursor::new(bytes);
        assert_eq!(rmp::decode::read_array_len(&mut cursor).unwrap(), 3);
        let login_password = deserialize_login_password(bytes, &mut cursor);

        let claims_len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let claims_bytes = cursor_slice(bytes, &mut cursor, claims_len);

        (login_password, BytePacked::new(claims_bytes))
    }

    pub fn deserialize(bytes: &'a [u8]) -> Self {
        let (
            LoginPassword {
                user_id,
                password_file,
            },
            claims,
        ) = Self::deserialize_tuple(bytes);

        Self {
            user_id,
            password_file,
            claims,
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

    pub fn cast<U: ByteSerial>(self) -> ByteOwned<U> {
        ByteOwned::<U>::new(self.bytes)
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

    pub fn try_deserialize(&self) -> Result<T::Deserialized<'_>, T::DeserializeErr> {
        T::try_deserialize(&self.bytes)
    }

    pub fn try_deserialize_owned(&self) -> Result<T, T::DeserializeErr> {
        T::try_deserialize_owned(&self.bytes)
    }

    pub fn cast<U: ByteSerial>(&self) -> &BytePacked<U> {
        BytePacked::<U>::new(&self.bytes)
    }
}

pub trait ByteSerial {
    type Deserialized<'a>
    where
        Self: 'a;
    type DeserializeErr: Debug;

    fn serialize(&self) -> ByteOwned<Self>
    where
        Self: Sized;

    fn try_deserialize(bytes: &[u8]) -> Result<Self::Deserialized<'_>, Self::DeserializeErr>;

    fn deserialize(bytes: &[u8]) -> Self::Deserialized<'_> {
        Self::try_deserialize(bytes).unwrap()
    }

    fn try_deserialize_owned(bytes: &[u8]) -> Result<Self, Self::DeserializeErr>
    where
        Self: Sized;

    fn deserialize_owned(bytes: &[u8]) -> Self
    where
        Self: Sized,
    {
        Self::try_deserialize_owned(bytes).unwrap()
    }
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

#[derive(Error, Debug)]
#[error("Bytes should be empty to deserialize as ().")]
pub struct NonEmptyBytes;

impl ByteSerial for () {
    type Deserialized<'a> = ();

    fn serialize(&self) -> ByteOwned<Self> {
        ByteOwned::new(Vec::with_capacity(0))
    }

    type DeserializeErr = NonEmptyBytes;

    fn try_deserialize(bytes: &[u8]) -> Result<Self::Deserialized<'_>, Self::DeserializeErr> {
        if bytes.is_empty() {
            return Ok(());
        } else {
            return Err(NonEmptyBytes);
        }
    }

    fn try_deserialize_owned(bytes: &[u8]) -> Result<Self, Self::DeserializeErr>
    where
        Self: Sized,
    {
        <Self as ByteSerial>::try_deserialize(bytes)
    }
}

// TODO make ByteSerial work for &str and other byte-native types
impl ByteSerial for String {
    type Deserialized<'a> = &'a str;

    fn serialize(&self) -> ByteOwned<Self> {
        ByteOwned::new(self.as_bytes().to_vec())
    }

    type DeserializeErr = Utf8Error;

    fn try_deserialize(bytes: &[u8]) -> Result<Self::Deserialized<'_>, Self::DeserializeErr> {
        std::str::from_utf8(bytes)
    }

    fn try_deserialize_owned(bytes: &[u8]) -> Result<Self, Self::DeserializeErr>
    where
        Self: Sized,
    {
        Ok(<Self as ByteSerial>::try_deserialize(bytes)?.to_owned())
    }
}

#[derive(Debug)]
pub enum SessionClaims {
    All,
    Some(Vec<String>),
}

impl SessionClaims {
    pub fn from_options(
        all_claims: Option<bool>,
        requested_claims: Option<Vec<String>>,
    ) -> Result<SessionClaims, &'static str> {
        if let Some(requested_claims) = requested_claims {
            if all_claims.is_some() && all_claims.unwrap() {
                return Err(
                    "Invalid requested claims! Cannot request all_claims: true and provide claims!",
                );
            }

            return Ok(SessionClaims::Some(requested_claims));
        } else if let Some(all_claims) = all_claims {
            if all_claims {
                return Ok(SessionClaims::All);
            }
        }

        Ok(SessionClaims::Some(Vec::new()))
    }

    pub fn from_subset_str(subset: Vec<&str>) -> Self {
        Self::Some(subset.into_iter().map(|s| s.to_owned()).collect())
    }

    pub fn from_subset(subset: Vec<String>) -> Self {
        Self::Some(subset)
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

#[derive(Serialize, Deserialize)]
#[repr(transparent)]
pub struct ClaimKeys(Vec<String>);

#[derive(Error, Debug)]
#[error("Unable to deserialize bytes as ClaimKeys.")]
pub struct InvalidClaimKeys;

impl ByteSerial for ClaimKeys {
    type Deserialized<'a> = Self;

    type DeserializeErr = InvalidClaimKeys;

    fn serialize(&self) -> ByteOwned<Self>
    {
        let bytes = rmp_serde::to_vec(&self).unwrap();
        ByteOwned::new(bytes)
    }

    fn try_deserialize(bytes: &[u8]) -> Result<Self::Deserialized<'_>, Self::DeserializeErr> {
        rmp_serde::decode::from_slice(bytes).map_err(|_| InvalidClaimKeys)
    }

    fn try_deserialize_owned(bytes: &[u8]) -> Result<Self, Self::DeserializeErr>
    {
        <Self as ByteSerial>::try_deserialize(bytes)
    }
}

#[derive(Error, Debug)]
#[error("Unable to deserialize bytes as ClaimsView.")]
pub struct InvalidClaimsBytes;

impl ByteSerial for Claims {
    type Deserialized<'a> = ClaimsView<'a>;

    fn serialize(&self) -> ByteOwned<Self> {
        let view = self.to_view();

        ByteOwned::new(view.to_vec())
    }

    type DeserializeErr = InvalidClaimsBytes;

    fn try_deserialize(bytes: &[u8]) -> Result<Self::Deserialized<'_>, Self::DeserializeErr> {
        let view: ClaimsView = rmp_serde::from_slice(bytes).map_err(|_| InvalidClaimsBytes)?;

        Ok(view)
    }

    /// Note that this is quite expensive, as it has to iterate and clone the data. You probably don't want to use this.
    fn try_deserialize_owned(bytes: &[u8]) -> Result<Self, Self::DeserializeErr>
    where
        Self: Sized,
    {
        let view = <Self as ByteSerial>::try_deserialize(bytes)?;
        let keys = view.keys.iter().map(|t| t.to_owned()).collect();
        let values = view.values.iter().map(|t| t.to_vec()).collect();
        Ok(Self { keys, values })
    }
}

static EMPTY_CLAIMS: OnceLock<ByteOwned<Claims>> = OnceLock::new();

pub fn empty_claim_bytes() -> &'static BytePacked<Claims> {
    EMPTY_CLAIMS
        .get_or_init(|| Claims::empty().serialize())
        .as_packed()
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
        Self { keys, values }
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

#[derive(Error, Debug)]
pub enum ModifyClaimError {
    #[error("Could not add claim: already exists!")]
    AddExists,
    #[error("Could not modify claims. User does not exist.")]
    UserNotFound,
    #[error("Could not modify claims. Claims are not sorted.")]
    NotSorted
}

#[derive(Error, Debug)]
#[error("Claim keys are not in ascending order.")]
pub struct ClaimsUnsortedError;

impl<'a> ClaimsView<'a> {
    pub fn add_claims<'b>(
        &self,
        claims: ClaimsView<'b>,
        exists_ok: bool,
    ) -> Result<Claims, ModifyClaimError> {
        let Claims { mut keys, mut values } = self.to_claims_sorted().map_err(|_| ModifyClaimError::NotSorted)?;
        let left_i = 0;

        for (claim, value) in claims.keys.iter().zip(claims.values.iter()) {
            let right_i = keys.len();
            let claim = claim.to_owned();
            match &keys[left_i..right_i].binary_search(&claim) {
                Ok(found_i) => {
                    if exists_ok {
                        values[*found_i+left_i] = value.to_owned();
                    } else {
                        return Err(ModifyClaimError::AddExists);
                    }
                }
                Err(not_found_i) => {
                    keys.insert(*not_found_i+left_i, claim);
                    values.insert(*not_found_i+left_i, value.to_owned())
                }
            }
        }

        Ok(Claims { keys, values})
    }

    pub fn remove_claims(
        &self,
        claim_keys: &ClaimKeys
    ) -> Result<Claims, ModifyClaimError> {
        if claim_keys.0.len() == 0 {
            return self.to_claims_sorted().map_err(|_| ModifyClaimError::NotSorted)
        }

        let mut keys: Vec<String> = Vec::with_capacity(self.keys.len());
        let mut values: Vec<Vec<u8>> = Vec::with_capacity(self.values.len());

        let mut i = 0;
        let mut current: &str = &claim_keys.0[i];
        for (claim, value) in self.keys.iter().zip(self.values.iter()) {
            if i >= claim_keys.0.len() || claim != current {
                keys.push(claim.to_owned());
                values.push(value.to_vec());
            } else if i < claim_keys.0.len()-1 {
                i += 1;
                let new_value = &claim_keys.0[i];
                if current > new_value {
                    return Err(ModifyClaimError::NotSorted);
                }
                current = new_value;
            }
        }

        Ok(Claims { keys, values})
    }

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

    /// In the future a more efficient way of creating varzerovec should be investigated
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

    pub fn to_vec(&self) -> Vec<u8> {
        rmp_serde::to_vec(&self).unwrap()
    }

    pub fn to_claims_sorted(&self) -> Result<Claims, ClaimsUnsortedError> {
        let mut keys: Vec<String> = Vec::with_capacity(self.keys.len());
        for i in 0..self.keys.len() {
            let current = &self.keys[i];
            if i != 0 {
                let prev = &self.keys[i-1];
                if prev < current {
                    return Err(ClaimsUnsortedError)
                }
            }

            keys.push(current.to_owned());
        }
        let values: Vec<Vec<u8>> = self.values.iter().map(|v| v.to_vec()).collect();
        Ok(Claims { keys, values })
    }
}

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

#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Clone)]
pub enum ActionType {
    #[serde(rename = "reset")]
    Reset,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "set")]
    Set,
    #[serde(rename = "add")]
    Add,
    #[serde(rename = "merge")]
    Merge,
    #[serde(rename = "read")]
    Read,
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
pub enum Target {
    #[serde(rename = "select")]
    Select,
    #[serde(rename = "range")]
    Range,
    #[serde(rename = "all")]
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
}

impl ActionType {
    fn name(&self) -> &'static str {
        match &self {
            Self::Reset => "reset",
            Self::Delete => "delete",
            Self::Read => "read",
            Self::Set => "set",
            Self::Add => "add",
            Self::Merge => "merge",
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

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, InvalidProof> {
        // let mut cursor = Cursor::new(bytes);
        let mut cursor = Cursor::new(bytes);

        let about = rmp_read_bin(bytes, &mut cursor).map_err(|_| InvalidProof {})?;
        let nonce = rmp_read_bin(bytes, &mut cursor).map_err(|_| InvalidProof {})?;
        let array_len = rmp::decode::read_array_len(&mut cursor).map_err(|_| InvalidProof {})?;
        let mut targets = Vec::new();

        for _ in 0..array_len {
            let target = rmp_read_str(bytes, &mut cursor).map_err(|_| InvalidProof {})?;
            targets.push(target.to_owned())
        }

        let data = rmp_read_bin(bytes, &mut cursor).map_err(|_| InvalidProof {})?;
        let data = BytePacked::new(data);

        let about: ProofAbout = rmp_serde::from_slice(about).map_err(|_| InvalidProof {})?;

        Ok(Self {
            about,
            nonce: nonce.to_owned(),
            target_data: TargetList(targets),
            data,
        })
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
            _ => Err(OneOf::new(InvalidProof {})),
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

    pub fn as_vec(self) -> Vec<String> {
        self.0
    }
}

pub struct AboutVerify {
    pub application: String,
    allowed_actions: HashSet<ActionType>,
}

impl AboutVerify {
    pub fn new(application: &str, action: ActionType) -> Self {
        Self {
            application: application.to_owned(),
            allowed_actions: HashSet::from_iter(vec![action]),
        }
    }

    pub fn with_allowed(application: &str, allowed: Vec<ActionType>) -> Self {
        Self {
            application: application.to_owned(),
            allowed_actions: HashSet::from_iter(allowed),
        }
    }

    // pub fn with_claims_actions(application: &str) -> Self {
    //     Self::with_allowed(
    //         application,
    //         vec![
    //             ActionType::Reset,
    //             ActionType::Merge,
    //             ActionType::Add,
    //             ActionType::Delete,
    //         ],
    //     )
    // }

    pub fn verify(&self, about: &ProofAbout) -> Result<(), InvalidProof> {
        if !self.allowed_actions.contains(&about.action) || self.application != about.application {
            return Err(InvalidProof {});
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use rand::{Rng, RngCore};

    use base64::{engine::general_purpose as b64, Engine as _};

    use super::*;

    #[test]
    fn serialize_login() {
        let claims = Claims::empty().serialize();

        let login = Login {
            user_id: "some_name".to_owned(),
            password_file: "pw".to_owned(),
            claims: claims.as_packed(),
        };

        let login_serial = login.serialize();

        let login_deser = Login::deserialize(&login_serial);

        assert_eq!(login, login_deser);
    }

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
