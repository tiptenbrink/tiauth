use std::collections::HashMap;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use lazy_borink::Lazy;
use napi::{bindgen_prelude::{Either3, FromNapiValue, Object, TypeName, Uint8Array, ValidateNapiValue}, Either, Error, JsObject, JsUnknown, ValueType};
use tiauth_app::ProofBase;
use tiauth_core::api::Claims;

#[macro_use]
extern crate napi_derive;

pub struct ClaimsArg(Claims);

impl FromNapiValue for ClaimsArg {
    unsafe fn from_napi_value(env: napi::sys::napi_env, napi_val: napi::sys::napi_value) -> napi::Result<Self> {
        let obj = JsObject::from_napi_value(env, napi_val)?;
        let keys = Object::keys(&obj)?;
        let mut map = HashMap::with_capacity(keys.len());
        for key in keys {
            if let Some(val) = obj.get::<&str, Either<Uint8Array, String>>(&key)? {
                let bytes = match val {
                    Either::A(bytes) => bytes.to_vec(),
                    Either::B(string) => string.into_bytes(),
                };
                
                map.insert(key, bytes);
            }
        }
    
        Ok(ClaimsArg(Claims(map)))
    }
}

// pub struct LazyArg<T>(Lazy<T>);

// impl<T> FromNapiValue for LazyArg<T> 
//     where T: FromNapiValue + TypeName + ValidateNapiValue
// {
//     unsafe fn from_napi_value(env: napi::sys::napi_env, napi_val: napi::sys::napi_value) -> napi::Result<Self> {
//         let either: Either3<T, String, Uint8Array> = Either3::from_napi_value(env, napi_val)?;
//     }
// }

#[napi(js_name = createSetClaimsProof)]
pub fn create_set_claims_proof_map(
    application: String,
    private_key_pem: String,
    user_id: String,
    #[napi(ts_arg_type = "Record<string, string | Uint8Array>")]
    claims: ClaimsArg,
) -> Result<String, Error> {
    let proof_base = ProofBase::new(&application, &private_key_pem);

    Ok(tiauth_app::create_set_claims_proof(
        proof_base, &user_id, claims.0.into(),
    ))
}

#[napi(js_name = createResetProof)]
pub fn create_reset_proof(application: String, private_key_pem: String, user_id: String) -> String {
    let proof_base = ProofBase::new(&application, &private_key_pem);

    tiauth_app::create_reset_proof(proof_base, &user_id)
}

#[napi(js_name = createReadAllProof)]
pub fn create_read_all_proof(application: String, private_key_pem: String) -> String {
    let proof_base = ProofBase::new(&application, &private_key_pem);

    tiauth_app::create_read_all_proof(proof_base)
}