use js_sys::{Array, Error, Object, Uint8Array};
use std::cmp::Ordering;
use tiauth_core::encoded::Encodable;
use tiauth_core::{app, ByteOwned, ByteSerial};
use tiauth_core::{
    app::ProofBaseView,
    crypto::{load_key, Key},
    Claims,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ProofKey {
    key: Key,
}

#[wasm_bindgen(js_name = createProofKey)]
pub fn create_proof_key(private_key_pem: String) -> Result<ProofKey, Error> {
    let key = load_key(&private_key_pem)
        .map_err(|_| Error::new("Failed to parse PEM file as Ed25519 private key."))?;
    println!("hi?");
    Ok(ProofKey { key })
}

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

        for (i, e) in entries.into_iter().enumerate() {
            let e: &Array = e.unchecked_ref();
            let key = e.get(0);
            let value = e.get(1);
            let k = if key.is_string() {
                key.as_string().unwrap()
            } else {
                return Err(Error::new("Key is not string!").into());
            };
            if i != 0 {
                let prev = &keys[i - 1];
                if let Ordering::Greater = prev.cmp(&k) {
                    return Err(Error::new("Claim keys are not sorted!").into());
                }
            }

            let v = if value.is_instance_of::<Uint8Array>() {
                let bytes: Uint8Array = value.unchecked_into();
                bytes.to_vec()
            } else if value.is_string() {
                key.as_string().unwrap().into_bytes()
            } else {
                return Err(Error::new("Value is not string or bytes!").into());
            };

            keys.push(k);
            values.push(v);
        }

        Claims::from_keys_values(keys, values).serialize()
    } else {
        return Err(Error::new("Cannot interpret claims argument as Claims type!").into());
    };

    Ok(app::create_set_claims_proof(proof_base, &user_id, claims.as_packed()).encode())
}

#[wasm_bindgen(js_name = createResetProof)]
pub fn create_reset_proof(application: String, key: &ProofKey, user_id: String) -> String {
    let proof_base = ProofBaseView::new(&application, &key.key);

    app::create_reset_proof(proof_base, &user_id).encode()
}

#[wasm_bindgen(js_name = createReadAllProof)]
pub fn create_read_all_proof(application: String, key: &ProofKey) -> String {
    let proof_base = ProofBaseView::new(&application, &key.key);

    app::create_read_all_proof(proof_base).encode()
}
