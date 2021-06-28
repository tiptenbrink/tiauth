use crate::{defs, files};
use crate::error::{ErrorReject, RejectTypes};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use crate::reject;

fn generate_keypair() -> (String, String) {
    let mut csprng = OsRng{};

    let keypair: Keypair = Keypair::generate(&mut csprng);

    (hex::encode(keypair.public.as_bytes()), hex::encode(keypair.secret.as_bytes()))
}

pub async fn write_user(
    user_json: defs::UserJson) -> Result<impl warp::Reply, warp::Rejection> {
    let f = files::open_user_file(&user_json.user_hex).await;
    let err = f.err();
    if err.is_some() {
        let err = err.unwrap();
        if files::io_is_nonexistent(&err) {
            let (public_hex, secret_hex): (String, String) = generate_keypair();
            files::register_user(&user_json, public_hex, secret_hex).await
                .map_err(|e| { reject(ErrorReject { rt: RejectTypes::IO,
                    msg: "Error writing user registration! (write user)",
                    e: e.to_string() }) })?;

            let empty_claims = defs::Tiauth {
                claims: vec![]
            };

            files::write_user_claims(&user_json.user_hex, &empty_claims).await
                .map_err(|e| { reject(ErrorReject { rt:RejectTypes::IO,
                    msg: "Error writing empty user claims! (write user)",
                    e: e.to_string() }) })?;

            Ok(warp::reply::json(&user_json))
        }
        else {
            Err(reject(ErrorReject { rt: RejectTypes::IO,
                msg: "Error opening user file (write user)",
                e: err.to_string()
            }))
        }
    }
    else {
        let appendix = format!("@@@user_hex: {}@@@", &user_json.user_hex);
        Err(reject(ErrorReject { rt: RejectTypes::AlreadyExists,
            msg: "User already exists!",
            e: appendix }))
    }
}