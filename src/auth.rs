use crate::files;
use crate::error::{ErrorReject, RejectTypes};
use ed25519_dalek::{PublicKey, Verifier};
use ed25519_dalek::ed25519::signature::Signature;
use warp::reject::custom as reject;

pub async fn verify_jwt(user_hex: &str, jwt: &str) -> Result<(), warp::Rejection> {
    let save_user = files::read_user(user_hex, false).await
        .map_err(|e| { files::io_nonexistent_reject(e, "Error reading user data (verify jwt)",
                                                    "User does not exist! (verify jwt)") })?;
    let public_key = hex::decode(&save_user.public_hex)
        .map_err(|e| { reject(ErrorReject { rt: RejectTypes::DecodeInternal,
            msg: "Error decoding public key hex! (verify jwt)",
            e: e.to_string()}) })?;
    let public_key = PublicKey::from_bytes(&public_key)
        .map_err(|e| { reject(ErrorReject { rt: RejectTypes::DecodeInternal,
            msg: "Error creating public key object from bytes! (verify jwt)",
            e: e.to_string()}) })?;

    let jwt_msg: String = jwt.split('.').take(2).collect::<Vec<&str>>().join(".");

    let signature_b64url = jwt.split('.').skip(2).collect::<String>();

    let signature_dec = base64_url::decode(&signature_b64url)
        .map_err(|e| { reject(ErrorReject { rt: RejectTypes::DecodeExternal,
            msg: "Error decoding jwt signature (verify jwt)",
            e: e.to_string()}) })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_dec)
        .map_err(|e| { reject(ErrorReject { rt: RejectTypes::DecodeExternal,
            msg: "Error creating signature object from jwt bytes! (verify jwt)",
            e: e.to_string()}) })?;

    Ok(public_key.verify(jwt_msg.as_bytes(), &signature)
        .map_err(|e| { reject(ErrorReject { rt: RejectTypes::Tampered,
            msg: "Rejected verification: tampered or malformed jwt!",
            e: e.to_string()}) })?)
}