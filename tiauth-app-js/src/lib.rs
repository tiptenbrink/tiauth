use lazy_borink::Lazy;
use tiauth_app::ProofBase;
use tiauth_core::api::Claims;
use wasm_bindgen::prelude::*;


#[wasm_bindgen(js_name = createClaims)]
pub fn create_claims(claims: JsValue) -> Result<Box<[u8]>, JsValue> {
    let lazy_claims: Lazy<Claims> = serde_wasm_bindgen::from_value(claims)?;

    Ok(lazy_claims.take_bytes().into_boxed_slice())
}

#[wasm_bindgen(js_name = createSetClaimsProof)]
pub fn create_set_claims_proof(
    application: &str,
    private_key_pem: &str,
    user_id: &str,
    claims: JsValue,
) -> Result<String, JsValue> {
    let lazy_claims: Lazy<Claims> = serde_wasm_bindgen::from_value(claims)?;

    let proof_base = ProofBase::new(application, private_key_pem);

    Ok(tiauth_app::create_set_claims_proof(
        proof_base, user_id, lazy_claims,
    ))
}

#[wasm_bindgen(js_name = createResetProof)]
pub fn create_reset_proof(application: &str, private_key_pem: &str, user_id: &str) -> Result<String, JsValue> {
    let proof_base = ProofBase::new(application, private_key_pem);

    Ok(tiauth_app::create_reset_proof(proof_base, user_id))
}

#[wasm_bindgen(js_name = createReadAllProof)]
pub fn create_read_all_proof(application: &str, private_key_pem: &str) -> Result<String, JsValue> {
    let proof_base = ProofBase::new(application, private_key_pem);

    Ok(tiauth_app::create_read_all_proof(proof_base))
}