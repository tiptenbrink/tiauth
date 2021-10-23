use crate::{Deserialize, Serialize};
use crate::files;
use std::time::SystemTime;
use ed25519_dalek::Signer;
use crate::error::{ErrorReject, RejectTypes};
use crate::params;
use crate::reject;

#[derive(Deserialize, Serialize)]
pub struct UserLogin {
    user_hex: String,
    password_hash_hex: String,
}

#[derive(Deserialize, Serialize)]
struct ClaimsJWTPayload {
    iss: String,
    iat: u64,
    sub: String,
    tipten_auth: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
struct JwtResponse {
    public_hex: String,
    jwt: String,
}

#[derive(Deserialize, Serialize)]
struct UserSalt {
    salt_hex: String,
}

#[derive(Deserialize, Serialize)]
struct UserPublic {
    public_hex: String,
}

const ED25519JWT: &str = r#"
        {
            "alg": "ED25519",
            "typ": "JWT
        }"#;

pub async fn reply_user_salt(
    user_hex_param: params::UserHex) -> Result<impl warp::Reply, warp::Rejection> {
    let user_hex = user_hex_param.user_hex;

    let save_user = files::read_user(&user_hex, false).await
        .map_err(|e| { files::io_nonexistent_reject(e, "Error reading user data (user salt)",
                                                    "User does not exist! (user salt)") })?;

    let user_salt = UserSalt {
        salt_hex: save_user.salt_hex,
    };

    Ok(warp::reply::json(&user_salt))
}

pub async fn reply_user_public(
    user_hex_param: params::UserHex) -> Result<impl warp::Reply, warp::Rejection> {
    let user_hex = user_hex_param.user_hex;
    let save_user = files::read_user(&user_hex, false).await
        .map_err(|e| { files::io_nonexistent_reject(e, "Error reading user data (user public)",
                                                    "User does not exist! (user public)") })?;

    let user_public = UserPublic {
        public_hex: save_user.public_hex,
    };

    Ok(warp::reply::json(&user_public))
}

pub async fn login_user(
    user_login: UserLogin) -> Result<impl warp::Reply, warp::Rejection> {

    let user_hex = &user_login.user_hex;

    let save_user = files::read_user(user_hex, true).await
        .map_err(|e| { files::io_nonexistent_reject(e, "Error reading user data (login user)",
                                                    "User does not exist! (login user)") })?;

    if save_user.password_hash_hex == user_login.password_hash_hex {
        let jwt_header = base64_url::encode(ED25519JWT);
        let claims = files::read_user_claims(user_hex).await
            .map_err(|e| { files::io_nonexistent_reject(e, "Error reading user claims (login user)",
                                                        "User claims do not exist! (login user)") })?;
        let claims = serde_json::to_value(claims)
            .map_err(|e| { reject(ErrorReject { rt: RejectTypes::DecodeInternal,
                msg: "Error converting to serde JSON Value (login_user)",
                e: e.to_string()
            }) })?;
        let n = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| { reject(ErrorReject { rt: RejectTypes::Internal,
                msg: "Error calculating system time (login_user)",
                e: e.to_string()
            }) })?.as_secs();

        let payload_obj = ClaimsJWTPayload {
            iss: "auth.tipten.nl".to_owned(),
            iat: n,
            sub: user_hex.to_owned(),
            tipten_auth: claims,
        };

        let mut keypair_bytes = hex::decode(&save_user.secret_hex)
            .map_err(|e| { reject(ErrorReject{ rt: RejectTypes::DecodeInternal,
                msg: "Error decoding saved user data (login user)",
                e: e.to_string()
            }) })?;
        keypair_bytes.append(&mut hex::decode(&save_user.public_hex)
            .map_err(|e| { reject(ErrorReject{ rt: RejectTypes::DecodeInternal,
                msg: "Error decoding saved user data (login user)",
                e: e.to_string()
            }) })?);
        let keypair = ed25519_dalek::Keypair::from_bytes(&keypair_bytes)
            .map_err(|e| { reject(ErrorReject{ rt: RejectTypes::DecodeInternal,
                msg: "Error decoding saved user data (login user)",
                e: e.to_string()
            }) })?;

        let jwt_payload_json = serde_json::to_string_pretty(&payload_obj)
            .map_err(|e| { reject(ErrorReject{ rt: RejectTypes::DecodeInternal,
                msg: "Error JSONing jwt payload (login user)",
                e: e.to_string()
            }) })?;
        let jwt_payload = base64_url::encode(&jwt_payload_json);
        let jwt_combined: String = jwt_header.clone() + "." + &jwt_payload;
        let jwt_combined_bytes = jwt_combined.as_bytes();

        let signature: ed25519_dalek::Signature = keypair.sign(jwt_combined_bytes);
        let public_hex = hex::encode(keypair.public.to_bytes());

        let jwt = JwtResponse {
            public_hex,
            jwt: (jwt_combined + "." + & base64_url::encode( &signature.to_bytes())),
        };

        Ok(warp::reply::json(&jwt))
    }
    else {
        Err(reject(ErrorReject {
            rt: RejectTypes::Incorrect,
            msg: "Input password is incorrect!",
            e: "".to_string()
        }))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn login_test() {

    }
}