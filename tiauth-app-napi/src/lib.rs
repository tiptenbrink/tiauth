use lazy_borink::Lazy;
use napi::{
    bindgen_prelude::{Either3, FromNapiValue, Object, TypeName, Uint8Array, ValidateNapiValue},
    Either, Error, JsObject, ValueType,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tiauth_core::app;
use tiauth_core::{
    app::ProofBaseView,
    crypto::{load_key, Key},
    Claims,
};

#[macro_use]
extern crate napi_derive;

#[derive(Serialize, Deserialize, Debug)]
pub struct ClaimsArg(Claims);

impl FromNapiValue for ClaimsArg {
    unsafe fn from_napi_value(
        env: napi::sys::napi_env,
        napi_val: napi::sys::napi_value,
    ) -> napi::Result<Self> {
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

impl TypeName for ClaimsArg {
    fn type_name() -> &'static str {
        "Claims"
    }

    fn value_type() -> ValueType {
        ValueType::Object
    }
}

impl ValidateNapiValue for ClaimsArg {}

#[napi]
pub struct ProofKey {
    key: Key,
}

pub struct LazyArg<T>(Lazy<T>);

impl<T> FromNapiValue for LazyArg<T>
where
    T: FromNapiValue + TypeName + ValidateNapiValue + core::fmt::Debug,
{
    unsafe fn from_napi_value(
        env: napi::sys::napi_env,
        napi_val: napi::sys::napi_value,
    ) -> napi::Result<Self> {
        let either: Either3<Uint8Array, String, T> = Either3::from_napi_value(env, napi_val)?;

        match either {
            Either3::A(b) => Ok(LazyArg(Lazy::from_bytes(b.to_vec()))),
            Either3::B(s) => Ok(LazyArg(Lazy::from_bytes(s.into_bytes()))),
            Either3::C(map) => Ok(LazyArg(map.into())),
        }
    }
}

#[napi(js_name = createProofKey)]
pub fn create_proof_key(private_key_pem: String) -> Result<ProofKey, Error> {
    let key = load_key(&private_key_pem)
        .map_err(|_| Error::from_reason("Failed to parse PEM file as Ed25519 private key."))?;

    Ok(ProofKey { key })
}

#[napi(js_name = createSetClaimsProof)]
pub fn create_set_claims_proof_map(
    application: String,
    key: &ProofKey,
    user_id: String,
    #[napi(ts_arg_type = "Record<string, string | Uint8Array> | Uint8Array | string")]
    claims: LazyArg<ClaimsArg>,
) -> Result<String, Error> {
    let proof_base = ProofBaseView::new(&application, &key.key);
    let lazy_claims = claims.0.map(|c| c.0);
    Ok(app::create_set_claims_proof(
        proof_base,
        &user_id,
        lazy_claims,
    ))
}

#[napi(js_name = createResetProof)]
pub fn create_reset_proof(application: String, key: &ProofKey, user_id: String) -> String {
    let proof_base = ProofBaseView::new(&application, &key.key);

    app::create_reset_proof(proof_base, &user_id)
}

#[napi(js_name = createReadAllProof)]
pub fn create_read_all_proof(application: String, key: &ProofKey) -> String {
    let proof_base = ProofBaseView::new(&application, &key.key);

    app::create_read_all_proof(proof_base)
}
