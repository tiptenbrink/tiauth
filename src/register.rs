use crate::{defs, files, db, req_body};
use rusqlite::Connection;
use crate::error::{ErrorReject, RejectTypes, RusqliteErrorPassExt, RejectableExt};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use warp::reject::custom as reject;

fn generate_keypair() -> (String, String) {
    let mut csprng = OsRng{};

    let keypair: Keypair = Keypair::generate(&mut csprng);

    (hex::encode(keypair.public.as_bytes()), hex::encode(keypair.secret.as_bytes()))
}

/// Registers a new user and writes it to the database
///
pub async fn write_user(
    user_register: req_body::UserRegister, db_id: &str) -> Result<impl warp::Reply, warp::Rejection> {

    let mut conn = Connection::open(db_id).rej(RejectTypes::IO, "Database failure (user public)")?;

    let exists = db::user_exists(&conn, &user_register.user_hex)
        .sql_rej("User existence check error (write user)")?;
    if !exists {
        let (public_hex, secret_hex): (String, String) = generate_keypair();

        let new_user = db::UserAuth {
            user_hex: user_register.user_hex.clone(),
            password_hash_hex: user_register.password_hash_hex.clone(),
            salt_hex: user_register.salt_hex.clone(),
            secret_hex,
            public_hex
        };

        db::add_user(&mut conn, new_user).sql_rej("(write user)")?;

        Ok(warp::reply())
    }
    else {
        let appendix = format!("@@@user_hex: {}@@@", &user_register.user_hex);
        Err(reject(ErrorReject { rt: RejectTypes::AlreadyExists,
            msg: "User already exists!",
            e: appendix }))
    }
}