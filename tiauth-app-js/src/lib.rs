use js_sys::{Array, Error, JsString, Object, Uint8Array};
// use napi::{
//     bindgen_prelude::{Either3, FromNapiValue, Object, TypeName, Uint8Array, ValidateNapiValue},
//     Either, Error, JsObject, ValueType,
// };
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use tiauth_core::{app, ByteOwned, BytePacked, ByteSerial};
use tiauth_core::{
    app::ProofBaseView,
    crypto::{load_key, Key},
    Claims,
};
use wasm_bindgen::prelude::*;
use base64::{engine::general_purpose as b64, Engine as _};
// #[macro_use]
// extern crate napi_derive;


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

// impl<T> TryFromJsValue for LazyArg<T> 
//     where T: TryFromJsValue
// {
//     type Error = JsError;

//     fn try_from_js_value(value: JsValue) -> Result<Self, Self::Error> {
//         LazyArg(Lazy::fr)
//     }
// }


#[wasm_bindgen(js_name = createSetClaimsProof)]
pub fn create_set_claims_proof_map(
    application: String,
    key: &ProofKey,
    user_id: String,
    claims: JsValue,
) -> Result<String, JsValue> {
    let proof_base = ProofBaseView::new(&application, &key.key);

    let claims = if claims.is_instance_of::<Uint8Array>() {
        let bytes: Uint8Array = claims.unchecked_into();
        ByteOwned::new(bytes.to_vec())
    } else if claims.is_object() {
        // TODO also support Map

        let entries = Object::entries(claims.unchecked_ref());
        let mut keys: Vec<String> = Vec::with_capacity(entries.length() as usize);
        let mut values: Vec<Vec<u8>> = Vec::with_capacity(entries.length() as usize);

        let mut i = 0;
        for e in entries {
            let e: &Array = e.unchecked_ref();
            let key = e.get(0);
            let value = e.get(1);
            let k = if key.is_string() {
                key.as_string().unwrap()
            } else {
                return Err(Error::new("Key is not string!").into())
            };
            if i != 0 {
                let prev = &keys[i-1];
                if let Ordering::Greater = prev.cmp(&k) {
                    return Err(Error::new("Claim keys are not sorted!").into())
                }
            }
            i += 1;

            let v = if value.is_instance_of::<Uint8Array>() {
                let bytes: Uint8Array = value.unchecked_into();
                bytes.to_vec()
            } else if value.is_string() {
                key.as_string().unwrap().into_bytes()
            } else {
                return Err(Error::new("Value is not string or bytes!").into())
            };

            keys.push(k);
            values.push(v);
        }
        
        Claims::from_keys_values(keys, values).serialize()
    } else {
        return Err(Error::new("Cannot interpret claims argument as Claims type!").into())
    };

    Ok(app::create_set_claims_proof(
        proof_base,
        &user_id,
        claims.as_packed(),
    ))
}

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

