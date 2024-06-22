#![allow(dead_code, unused_imports)]

use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};
use rmp_serde::decode;
use lazy_borink::Lazy;
use tiauth_core::crypto::{create_key, load_key, save_key};
use base64::{engine::general_purpose as b64, Engine as _};
use tiauth_core::api::{Claims, Proof, ProofScope};

mod app3;

pub use app3::*;

pub fn create_private_key_pem() -> String {
    let key = create_key();

    save_key(&key).private
}

pub fn public_from_private_key_pem(private_key_pem: &str) -> String {
    let key = load_key(private_key_pem);

    save_key(&key).public
}

// pub trait LazyOr<T> {
//     fn as_lazy(self) -> Lazy<T>;
// }

// impl<T> LazyOr<T> for T {
//     fn as_lazy(self) -> Lazy<T> {
//         Lazy::from_inner(self)
//     }
// }

// impl<T> LazyOr<T> for Lazy<T> {
//     fn as_lazy(self) -> Lazy<T> {
//         self
//     }
// }

// pub fn gen_claims() -> Lazy<Claims> {
//     let mut rng = StdRng::from_entropy();
//     let mut buf = [0u8; 16];
//     rng.fill_bytes(&mut buf);
//     let enc = b64::URL_SAFE_NO_PAD.encode(buf);

//     let lazy_bytes = Lazy::from_inner(Claims::new(vec![("some_key", enc)])).take_bytes();

//     Lazy::from_bytes(lazy_bytes)
// }


// fn set_claims_proof_use<C: LazyOr<Claims>>(user_id: &str, claims: C) -> Lazy<ProofScope> {
//     let proof_use = ProofScope::SetClaims { user_id: user_id.to_owned(), claims: claims.as_lazy().take() };

//     Lazy::from_inner(proof_use)
// }

// fn create_proof_struct(proof_use: Lazy<ProofScope>, application: &str, private_key_pem: &str, expires_in: Option<u64>) -> Lazy<Proof> {
//     let key = load_key(private_key_pem);
    
//     Lazy::from_inner(Proof::create(&mut StdRng::from_entropy(), &key, application, expires_in, proof_use))
// }

// /// ProofScope encoded as MessagePack bytes, private key is PEM encoded PKCS#8 Ed448, returns MessagePack proof bytes.
// pub fn create_proof_json(proof_use: &[u8], application: &str, private_key_pem: &str, expires_in: Option<u64>) -> String {
//     let proof = create_proof_struct(proof_use, application, private_key_pem, expires_in);

//     serde_json::to_string(&Lazy::from_inner(proof)).unwrap()
// }

// pub fn create_proof(proof_use: &[u8], application: &str, private_key_pem: &str, expires_in: Option<u64>) -> Vec<u8> {
//     let proof = create_proof_struct(proof_use, application, private_key_pem, expires_in);

//     rmp_serde::encode::to_vec_named(&Lazy::from_inner(proof)).unwrap()
// }