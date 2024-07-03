use napi::{
    bindgen_prelude::{FromNapiValue, Object, Uint8Array},
    Either, Error, JsObject,
};
use std::cmp::Ordering;
use tiauth_core::{app, ByteOwned, BytePacked, ByteSerial};
use tiauth_core::{
    app::ProofBaseView,
    crypto::{load_key, Key},
    Claims,
};

#[macro_use]
extern crate napi_derive;

impl FromNapiValue for ClaimsSerialized {
    unsafe fn from_napi_value(
        env: napi::sys::napi_env,
        napi_val: napi::sys::napi_value,
    ) -> napi::Result<Self> {
        let obj = JsObject::from_napi_value(env, napi_val)?;
        let ob_keys = Object::keys(&obj)?;
        let mut keys: Vec<String> = Vec::with_capacity(ob_keys.len());
        let mut values: Vec<Vec<u8>> = Vec::with_capacity(ob_keys.len());

        for (i, key) in ob_keys.into_iter().enumerate() {
            if i != 0 {
                let prev = &keys[i - 1];
                if let Ordering::Greater = prev.cmp(&key) {
                    return Err(Error::from_reason("Claim keys are not sorted!"));
                }
            }

            if let Some(val) = obj.get::<&str, Either<Uint8Array, String>>(&key)? {
                let bytes = match val {
                    Either::A(bytes) => bytes.to_vec(),
                    Either::B(string) => string.into_bytes(),
                };

                keys.push(key);
                values.push(bytes);
            }
        }

        let claims = Claims::from_keys_values(keys, values);

        Ok(ClaimsSerialized::Serialized(claims.serialize()))
    }
}

#[napi]
pub struct ProofKey {
    key: Key,
}

pub enum ClaimsSerialized {
    Serialized(ByteOwned<Claims>),
}

impl ClaimsSerialized {
    fn as_bytes(&self) -> &BytePacked<Claims> {
        match &self {
            Self::Serialized(byte_owned) => byte_owned.as_packed(),
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
    #[napi(ts_arg_type = "Record<string, string | Uint8Array> | Uint8Array")]
    claims: ClaimsSerialized,
) -> Result<String, Error> {
    let proof_base = ProofBaseView::new(&application, &key.key);

    Ok(app::create_set_claims_proof(
        proof_base,
        &user_id,
        claims.as_bytes(),
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
