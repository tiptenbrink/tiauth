#![allow(dead_code)]

use crate::crypto::{self, load_public_key, sign_data, Key, PublicKey, SavedPublicKey, SessionKey};
use crate::util::{cursor_slice, nonce_384_bytes};
use base64::{engine::general_purpose as b64, Engine as _};
use rmp::decode::bytes::BytesReadError;
use rmp::decode::RmpRead;
use serde_bytes::ByteBuf;
use lazy_borink::Lazy;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rmp_serde::encode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zerovec::maps::ZeroVecLike;
use zerovec::vecs::Index32;
use zerovec::VarZeroVec;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::io::{Cursor, Read};
use std::marker::PhantomData;
use std::ops::Range;
use std::str;
/// This is necessary because SystemTime is not implemented on the WASM target. The web_time crate calls Date.now() instead.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use web_time::SystemTime;
#[cfg(any(not(target_family="wasm"), not(target_os="unknown")))]
use std::time::SystemTime;
use terrors::OneOf;
use thiserror::Error;

#[derive(Debug, PartialEq)]
struct ClaimsBytes(ByteBuf);

#[derive(Debug, PartialEq)]
pub struct Login<'a> {
    pub user_id: String,
    pub password_file: String,
    pub claims: BytePacked<'a, Claims>,
}

#[derive(Debug, PartialEq)]
pub struct LoginPassword {
    pub user_id: String,
    pub password_file: String
}

fn deserialize_login_password(bytes: &[u8], cursor: &mut Cursor<&[u8]>) -> LoginPassword {
    let user_id_len = rmp::decode::read_str_len(cursor).unwrap();
    let user_id_bytes = cursor_slice(bytes, cursor, user_id_len);
    let user_id = std::str::from_utf8(user_id_bytes).unwrap().to_owned();

    let pw_len = rmp::decode::read_str_len(cursor).unwrap();
    let pw_bytes = cursor_slice(bytes, cursor, pw_len);
    let password_file = std::str::from_utf8(pw_bytes).unwrap().to_owned();

    LoginPassword { user_id, password_file }
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
        
        let LoginPassword { user_id, password_file } = deserialize_login_password(bytes, &mut cursor);

        let claims_len = rmp::decode::read_bin_len(&mut cursor).unwrap();
        let claims_bytes = cursor_slice(bytes, &mut cursor, claims_len);

        Self {
            user_id,
            password_file,
            claims: BytePacked::new(claims_bytes)
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct BytePacked<'a, T> 
{
    bytes: &'a [u8],
    phantom: PhantomData<T>
}

// pub trait BytePackable {
//     fn to_bytes(&self) -> &[u8];

//     fn to_packed<'a>(&'a self) -> BytePacked<'a, Self> where Self: Sized {
//         BytePacked::new(&self.to_bytes())
//     }
// }

impl<'a, T> BytePacked<'a, T>
{
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            phantom: PhantomData
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn empty() -> Self {
        Self {
            bytes: &[],
            phantom: PhantomData
        }
    }
}

pub trait ByteSerial {
    fn serialize(&self) -> Vec<u8>;

    fn deserialize(bytes: &[u8]) -> &Self;

    // fn deserialize_owned(bytes: &[u8]) -> Self;
}

// #[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
// #[serde(transparent)]
// #[derive(Default)]
// pub struct Claims(pub HashMap<String, Vec<u8>>);

#[derive(Debug, PartialEq)]
pub struct Claims {

}


pub struct ClaimsZero<'a> {
    keys: VarZeroVec<'a, str, Index32>,
    values: VarZeroVec<'a, [u8], Index32>
}

use rayon::iter::walk_tree;
use rayon::prelude::*;
use std::sync::mpsc::{self, Sender};

impl<'a> ClaimsZero<'a> {
    /// If k is generally a fraction of n, doing linear search is almost always better. However, when k is a power of n (k = k^C) where C < 1, at some point doing binary search is faster.
    /// For C < 0.6, even for small n binary search is almost just as fast as linear. For larger n though binary search is faster even at far greater k than just k^C.
    /// If using binary search for each item on the original vec, for a subset of size k out of n claims, we would have O(k ln2(n)). 
    /// You can be slightly smarter if the subset is sorted, as we can eliminate everything to the left of the value we find as we iterate through the subset. However, in the worst case
    /// this only eliminates 1 at a time, but it's still always better.
    /// Smarter still, you pick the middle element from the subset, allowing you to split the claims in two. Now the left part of the subset can only be in the left part of the claims,
    /// and the right part of the subset only in the right part of the claims. This even allows parallelizing. 
    fn subset() {
        
    }

    pub fn subset_linear(&self, subset: Vec<String>) -> Vec<(String, Vec<u8>)> {
        let subset_len = subset.len();
        let mut subset_claims:  Vec<(String, Vec<u8>)> = Vec::with_capacity(subset_len);
        assert!(subset_len > 0);
        let mut i = 0;
        let mut n = 0;
        let mut current = &subset[i];

        for (k_i, k) in self.keys.iter().enumerate() {
            n += 1;
            if current == k {
                subset_claims.push((k.to_string(), self.values[k_i].to_vec()));
                i += 1;
                if i == subset.len() {
                    break;
                } else {
                    current = &subset[i];
                }
            }
        }
        println!("linear: {} ops.", n);
        subset_claims
    }

    pub fn subset_binary(&self, subset: Vec<String>) -> Vec<(String, Vec<u8>)> {
        let mut subset_claims:  Vec<(String, Vec<u8>)> = Vec::with_capacity(subset.len());
        let keys_len = self.keys.len();
        assert!(subset.len() > 0);
        let mut range = 0..keys_len;
        let mut i = 0f32;
        for s in &subset {
            i += (range.len() as f32).log2();
            if let Ok(rel_k_i) = self.keys.binary_search_in_range(&s, range.clone()).unwrap() {
                let k_i = rel_k_i+range.start;
                subset_claims.push((s.to_string(), self.values[k_i].to_vec()));
                // TODO check for out of bounds
                range = (k_i+1)..keys_len;
            }
        }
        println!("binary est: {} ops.", i);
        subset_claims
    }

    pub fn subset_binary_split_o(&self, subset: Vec<String>) -> Vec<(String, Vec<u8>)> {
        let mut subset_claims:  Vec<(String, Vec<u8>)> = Vec::with_capacity(subset.len());
        
        let start = 0;
        let end = self.keys.len();

        let mut queue: Vec<(Range<usize>, &[String])> = vec![(start..end, &subset)];
        let mut i = 0f32;
        while queue.len() > 0 {
            let (range, subset_slice) = queue.pop().unwrap();
            if subset_slice.len() == 0 {
                continue;
            }

            let middle_element_i = subset_slice.len()/2;
            let middle_element = &subset_slice[middle_element_i];
            i += (range.len() as f32).log2();
            if let Ok(rel_k_i) = self.keys.binary_search_in_range(middle_element, range.clone()).unwrap() {
                let k_i = rel_k_i+range.start;
                subset_claims.push((middle_element.to_string(), self.values[k_i].to_vec()));
                
                let left = range.start..k_i;
                let right = k_i+1..range.end;

                queue.push((left, &subset_slice[0..middle_element_i]));
                queue.push((right, &subset_slice[middle_element_i+1..subset_slice.len()]));
            } else {
                panic!("All elements in subset must be present!");
            }
        }
        println!("binary split: {} ops.", i);

        subset_claims
    }

    pub fn subset_binary_split(&self, subset: Vec<String>) -> Vec<(String, Vec<u8>)> {
        let mut subset_claims: Vec<(String, Vec<u8>)> = Vec::with_capacity(subset.len());
        
        let start = 0;
        let end = self.keys.len();

        let (send, receive) = mpsc::channel();

        let i = self.process_slice(start..end, &subset, send);
        while let Ok(k_i) = receive.recv() {
            subset_claims.push((self.keys[k_i].to_string(), self.values[k_i].to_vec()));
        }
        println!("binary split par: {} ops.", i);

        subset_claims
    }

    fn process_slice(&self, range: Range<usize>, subset_slice: &[String], sender: Sender<usize>) -> f32 {
        if subset_slice.is_empty() {
            return 0f32;
        }

        let middle_element_i = subset_slice.len() / 2;
        let middle_element = &subset_slice[middle_element_i];
        let ops = (range.len() as f32).log2();
        if let Ok(rel_k_i) = self.keys.binary_search_in_range(middle_element, range.clone()).unwrap() {
            let k_i = rel_k_i + range.start;
            
            assert_eq!(middle_element, &self.keys[k_i]);
            sender.send(k_i).unwrap();
            //subset_claims.push((middle_element.to_string(), self.values[k_i].to_vec()));

            let left = range.start..k_i;
            let right = k_i+1..range.end;

            let (l_o, r_o) = rayon::join(
                || self.process_slice(left, &subset_slice[0..middle_element_i], sender.clone()),
                || self.process_slice(right, &subset_slice[middle_element_i + 1..subset_slice.len()], sender.clone()),
            );

            l_o + r_o + ops
        } else {
            panic!("All elements in subset must be present!");
        }
    }

    pub fn subset_binary_split_oc(&self, subset: Vec<String>) -> Vec<(String, Vec<u8>)> {
        //let mut subset_claims: Vec<(String, Vec<u8>)> = Vec::with_capacity(subset.len());
        
        let start = 0;
        let end = self.keys.len();

        //let mut queue: Vec<(Range<usize>, &[String])> = vec![(start..end, &subset)];


        let (subset_claims, i) = self.process_slice_o(start..end, &subset);

        // while !queue.is_empty() {
        //     let (range, subset_slice) = queue.pop().unwrap();
        //     if subset_slice.is_empty() {
        //         continue;
        //     }

        //     let middle_element_i = subset_slice.len() / 2;
        //     let middle_element = &subset_slice[middle_element_i];
        //     i += (range.len() as f32).log2();
            
        //     if let Ok(rel_k_i) = self.keys.binary_search_in_range(middle_element, range.clone()).unwrap() {
        //         let k_i = rel_k_i + range.start;
        //         subset_claims.push((middle_element.to_string(), self.values[k_i].to_vec()));
                
        //         let left = range.start..k_i;
        //         let right = k_i+1..range.end;

        //         // Use rayon to process the left and right slices in parallel
        //         let (left_claims, right_claims): (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>) = rayon::join(
        //             || self.process_slice_o(left, &subset_slice[0..middle_element_i]),
        //             || self.process_slice_o(right, &subset_slice[middle_element_i + 1..subset_slice.len()])
        //         );
                
        //         subset_claims.extend(left_claims);
        //         subset_claims.extend(right_claims);
        //     } else {
        //         panic!("All elements in subset must be present!");
        //     }
        // }
        println!("binary split par extend: {} ops.", i);

        subset_claims
    }

    fn process_slice_o(&self, range: Range<usize>, subset_slice: &[String]) -> (Vec<(String, Vec<u8>)>, f32) {
        let mut claims = Vec::with_capacity(subset_slice.len());
        if subset_slice.is_empty() {
            return (claims, 0f32);
        }

        let middle_element_i = subset_slice.len() / 2;
        let middle_element = &subset_slice[middle_element_i];

        let mut ops = (range.len() as f32).log2();

        if let Ok(rel_k_i) = self.keys.binary_search_in_range(middle_element, range.clone()).unwrap() {
            let k_i = rel_k_i + range.start;
            claims.push((middle_element.to_string(), self.values[k_i].to_vec()));

            let left = range.start..k_i;
            let right = k_i+1..range.end;

            let ((left_claims, l_ops), (right_claims, r_ops)) = rayon::join(
                || self.process_slice_o(left, &subset_slice[0..middle_element_i]),
                || self.process_slice_o(right, &subset_slice[middle_element_i + 1..subset_slice.len()])
            );

            ops += l_ops + r_ops;

            claims.extend(left_claims);
            claims.extend(right_claims);
        } else {
            panic!("All elements in subset must be present!");
        }

        (claims, ops)
    }

    

    // pub fn subset_binary_rayon(&self, subset: Vec<String>) -> Vec<(String, Vec<u8>)> {

    //     let par_iter = walk_tree(4, |&e| {
    //         if e <= 2 {
    //             Vec::new()
    //         } else {
    //             vec![e / 2, e / 2 + 1]
    //         }
    //     });

    //     ()
    // }

    
}

// impl Claims {
//     pub fn new<S, V>(map: Vec<(S, V)>) -> Self
//     where
//         S: Into<String>,
//         V: AsRef<[u8]>,
//     {
//         Self(HashMap::from_iter(
//             map.into_iter()
//                 .map(|(s, v)| (s.into(), v.as_ref().to_vec())),
//         ))
//     }

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
    /// They are a msgpack map
    pub session_claims: BytePacked<'a, Claims>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionCreate<'a> {
    application: &'a str,
    user_id: &'a str,
    issued: u64,
    expires: u64
}

impl<'a> SessionContent<'a> {
    pub fn new(
        application: &str,
        user_id: &str,
        issued: u64,
        expires: u64,
        session_claims: BytePacked<'a, Claims>,
    ) -> Self {

        Self { user_id: user_id.to_owned(), application: application.to_owned(), issued, expires, session_claims }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let about = SessionCreate {
            application: &self.application, user_id: &self.user_id, issued: self.issued, expires: self.expires
        };
        let about_bytes = rmp_serde::encode::to_vec(&about).unwrap();
        rmp::encode::write_bin(&mut buf, &about_bytes).unwrap();
        rmp::encode::write_bin(&mut buf, &self.session_claims.as_bytes()).unwrap();

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
    
        Self { user_id: about.user_id.to_owned(), application: about.application.to_owned(), issued: about.issued, expires: about.expires, session_claims: BytePacked::new(claims) }
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
{
    pub about: ProofAbout,
    pub nonce: Vec<u8>,
    pub target_data: TargetList,
    pub data: BytePacked<'a, T>,
}

impl<'a, T> ProofContent<'a, T> {
    pub fn new(
        application: &str,
        expires: u64,
        action: ActionType,
        target: Target,
        target_data: TargetList,
        data: BytePacked<'a, T>,
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
        rmp::encode::write_bin(&mut buf, &self.data.as_bytes()).unwrap();

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
            data
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



// impl<T> ProofContent<T> {
//     pub fn new(
//         application: &str,
//         expires: u64,
//         action: ActionType,
//         target: Target,
//         target_data: Lazy<Vec<String>>,
//         data: Lazy<T>,
//     ) -> Self {
//         let nonce = nonce_384_bytes(&mut StdRng::from_entropy());

//         Self {
//             about: ProofAbout {
//                 application: application.to_owned(),
//                 expires,
//                 action,
//                 target,
//             },
//             nonce,
//             target_data,
//             data,
//         }
//     }

//     pub fn select_one(&mut self) -> Result<String, OneOf<(InvalidProof,)>> {
//         let targets = self.target_data.inner();

//         match self.about.target {
//             Target::Select => {
//                 if targets.len() == 1 {
//                     Ok(targets[0].clone())
//                 } else {
//                     Err(OneOf::new(InvalidProof {}))
//                 }
//             }
//             Target::All => Err(OneOf::new(InvalidProof {})),
//         }
//     }
// }

// #[derive(Debug, Serialize, Deserialize, Clone)]
// struct ProofInner<T> {
//     #[serde(bound(deserialize = "T: DeserializeOwned"))]
//     proof: Lazy<ProofContent<T>>,
//     signature: Vec<u8>,
// }

// impl<T> ProofInner<T>
// where
//     T: Serialize + core::fmt::Debug,
// {
//     fn new(proof_content: ProofContent<T>, key: &Key) -> Self {
//         let mut proof_content = Lazy::from_inner(proof_content);
//         let signature = sign_data(key, proof_content.bytes());

//         Self {
//             proof: proof_content,
//             signature,
//         }
//     }
// }

// /// Proof is not meant to be serializable, as it should be opaque and serialized only as bytes, e.g. using Lazy.
// #[derive(Debug, Deserialize, Clone)]
// #[serde(transparent)]
// pub struct Proof<T> {
//     #[serde(bound(deserialize = "T: DeserializeOwned"))]
//     inner: ProofInner<T>,
// }

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
        Self(Vec::new().into())
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
    use zerovec::{maps::MutableZeroVecLike, vecs::VarZeroVecOwned};

    use super::*;

    #[test]
    fn create_claims_subset() {
        let start = Instant::now();
        
        let mut rng = StdRng::from_entropy();
        let mut s = [0u8; 5000];

        let mut subset = Vec::new();
        let mut keys_in = Vec::new();
        let mut values_in: Vec<Vec<u8>> = Vec::new();
        let r_end: u32 = 20000;
        let sub_size = 200;
        let r: Range<u32> = 0..r_end;
        
        println!("elapsed pre: {} ms", start.elapsed().as_secs_f32()*1000f32);
        
        for i in r {
            let mut snow = Instant::now();
            //println!("elapsed 1: {} ms", snow.elapsed().as_secs_f32()*1000f32);
            rng.fill_bytes(&mut s);
            //println!("elapsed 2: {} ms", snow.elapsed().as_secs_f32()*1000f32);
            let s_str = b64::URL_SAFE_NO_PAD.encode(&s);
            //println!("elapsed 3: {} ms", snow.elapsed().as_secs_f32()*1000f32);
            let mut val = i.to_le_bytes().to_vec();
            val.extend(s_str.as_bytes());
            keys_in.push(s_str);
            //println!("elapsed 4: {} ms", snow.elapsed().as_secs_f32()*1000f32);
            
            //println!("elapsed 5: {} ms", snow.elapsed().as_secs_f32()*1000f32);
            values_in.push(val.to_vec());
            //println!("elapsed 6: {} ms", snow.elapsed().as_secs_f32()*1000f32);

        }
        println!("elapsed fill: {} ms", start.elapsed().as_secs_f32()*1000f32);

        keys_in.sort_unstable();

        println!("elapsed sort: {} ms", start.elapsed().as_secs_f32()*1000f32);
        
        for k in &keys_in {
            let f: f32 = rng.gen();
            //keys.push(&k);
            if f < (sub_size as f32 / r_end as f32 * 1.1) {
                subset.push(k.clone());
            }
        }
        println!("elapsed keys: {} ms", start.elapsed().as_secs_f32()*1000f32);

        println!("k={}, n={}", subset.len(), values_in.len());

        //println!("{:?}", keys);

        // let keys = keys.as_varzerovec();
        // let values = values.as_varzerovec();
        let keys: VarZeroVec<str, Index32> = VarZeroVec::from(&keys_in);
        let values: VarZeroVec<[u8], Index32> = VarZeroVec::from(&values_in);

        println!("elapsed conv: {} ms", start.elapsed().as_secs_f32()*1000f32);

        let claims = ClaimsZero {
            keys,
            values
        };
        let t = Instant::now();
        let mut s1 = claims.subset_linear(subset.clone());
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32()*1000f32);
        assert_eq!(s1.len(), subset.len());
        s1.sort();
        //println!("elapsed s1 srt: {} ms", start.elapsed().as_secs_f32()*1000f32);
        //println!("s1 {:?}", s1);
        let t = Instant::now();
        let mut s2 = claims.subset_binary(subset.clone());
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32()*1000f32);
        assert_eq!(s2.len(), subset.len());
        s2.sort();
        //println!("elapsed s2 srt: {} ms", start.elapsed().as_secs_f32()*1000f32);
        assert_eq!(s1, s2);
        //println!("s2 {:?}", s2);
        let t = Instant::now();
        let mut s3 = claims.subset_binary_split(subset.clone());
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32()*1000f32);
        assert_eq!(s3.len(), subset.len());
        s3.sort();
        //println!("elapsed s3 srt: {} ms", start.elapsed().as_secs_f32()*1000f32);
        assert_eq!(s1, s3);

        let t = Instant::now();
        let mut s4 = claims.subset_binary_split_o(subset.clone());
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32()*1000f32);
        assert_eq!(s4.len(), subset.len());
        s4.sort();
        //println!("elapsed s3 srt: {} ms", start.elapsed().as_secs_f32()*1000f32);
        assert_eq!(s1, s4);

        let t = Instant::now();
        let mut s5 = claims.subset_binary_split_oc(subset.clone());
        let t_e = Instant::now();
        println!("took {} ms.", t_e.duration_since(t).as_secs_f32()*1000f32);
        assert_eq!(s5.len(), subset.len());
        s5.sort();
        //println!("elapsed s3 srt: {} ms", start.elapsed().as_secs_f32()*1000f32);
        assert_eq!(s1, s5);
    }

    fn test_subset() {

    }
}