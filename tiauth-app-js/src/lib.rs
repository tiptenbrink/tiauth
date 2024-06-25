use js_sys::Error;
use lazy_borink::Lazy;
// use napi::{
//     bindgen_prelude::{Either3, FromNapiValue, Object, TypeName, Uint8Array, ValidateNapiValue},
//     Either, Error, JsObject, ValueType,
// };
use serde::{Deserialize, Serialize};
use tiauth_core::crypto::save_private_key;
use std::collections::HashMap;
use tiauth_core::app;
use tiauth_core::{
    app::ProofBaseView,
    crypto::{load_key, Key},
    Claims,
};
use wasm_bindgen::prelude::*;

// #[macro_use]
// extern crate napi_derive;

#[derive(Serialize, Deserialize, Debug)]
pub struct ClaimsArg(Claims);

// impl FromNapiValue for ClaimsArg {
//     unsafe fn from_napi_value(
//         env: napi::sys::napi_env,
//         napi_val: napi::sys::napi_value,
//     ) -> napi::Result<Self> {
//         let obj = JsObject::from_napi_value(env, napi_val)?;
//         let keys = Object::keys(&obj)?;
//         let mut map = HashMap::with_capacity(keys.len());
//         for key in keys {
//             if let Some(val) = obj.get::<&str, Either<Uint8Array, String>>(&key)? {
//                 let bytes = match val {
//                     Either::A(bytes) => bytes.to_vec(),
//                     Either::B(string) => string.into_bytes(),
//                 };

//                 map.insert(key, bytes);
//             }
//         }

//         Ok(ClaimsArg(Claims(map)))
//     }
// }

// impl TypeName for ClaimsArg {
//     fn type_name() -> &'static str {
//         "Claims"
//     }

//     fn value_type() -> ValueType {
//         ValueType::Object
//     }
// }

// impl ValidateNapiValue for ClaimsArg {}

#[wasm_bindgen]
pub struct ProofKey {
    key: Key,
}

// pub struct LazyArg<T>(Lazy<T>);

// impl<T> FromNapiValue for LazyArg<T>
// where
//     T: FromNapiValue + TypeName + ValidateNapiValue + core::fmt::Debug,
// {
//     unsafe fn from_napi_value(
//         env: napi::sys::napi_env,
//         napi_val: napi::sys::napi_value,
//     ) -> napi::Result<Self> {
//         //let now = Instant::now();
//         //let b = Uint8Array::from_napi_value(env, napi_val)?;

//         // let l = LazyArg(Lazy::from_bytes(b.to_vec()));
//         let either: Either3<Uint8Array, String, T> = Either3::from_napi_value(env, napi_val)?;
//         // let inm = Lazy::from_inner(T::from_napi_value(env, napi_val)?);
//         // //println!("{:?}", inm);
//         // let l: LazyArg<T> = LazyArg(inm);
//         // let after = Instant::now();

//         //println!("to rust: {}", after.duration_since(now).as_secs_f64()*1000f64);

//         match either {
//             Either3::A(b) => Ok(LazyArg(Lazy::from_bytes(b.to_vec()))),
//             Either3::B(s) => Ok(LazyArg(Lazy::from_bytes(s.into_bytes()))),
//             Either3::C(map) => Ok(LazyArg(map.into())),
//         }
//     }
// }

#[wasm_bindgen(js_name = createProofKey)]
pub fn create_proof_key(private_key_pem: String) -> Result<ProofKey, Error> {
    let key = load_key(&private_key_pem)
        .map_err(|_| Error::new("Failed to parse PEM file as Ed25519 private key."))?;
    println!("hi?");
    Ok(ProofKey { key })
}


// #[wasm_bindgen(js_name = createSetClaimsProof)]
// pub fn create_set_claims_proof_map(
//     application: String,
//     key: &ProofKey,
//     user_id: String,
//     claims: LazyArg<ClaimsArg>,
// ) -> Result<String, Error> {
//     let proof_base = ProofBaseView::new(&application, &key.key);
//     let b = claims.0.take();
//     Ok(app::create_set_claims_proof(
//         proof_base,
//         &user_id,
//         Lazy::from_inner(b.0),
//     ))
// }

#[wasm_bindgen(js_name = createResetProof)]
pub fn create_reset_proof(application: String, key: &ProofKey, user_id: String) -> String {
    let proof_base = ProofBaseView::new(&application, &key.key);
    
    app::create_reset_proof(proof_base, &user_id)
}

#[wasm_bindgen(js_name = createReadAllProof)]
pub fn create_read_all_proof(application: String, key: &ProofKey) -> String {
    let proof_base = ProofBaseView::new(&application, &key.key);

    app::create_read_all_proof(proof_base)
}

