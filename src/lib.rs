pub mod files;
pub mod error;
pub mod claims;
pub mod login;
pub mod auth;
pub mod register;

use error::ErrorReject;
use error::RejectType;
use warp::{Filter};
use warp::path;
use serde::{Deserialize, Serialize};
use warp::reject::custom as reject;
use warp::http::StatusCode;
use env_logger::Env;
use log::debug;

mod defs {
    use super::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct UserJson {
        pub user_hex: String,
        pub password_hash_hex: String,
        pub salt_hex: String,
    }

    #[derive(Deserialize, Serialize, Debug)]
    pub struct UserClaim {
        pub origin: String,
        pub anphd_id: String,
        pub uuid: String,
        pub permission: u16,
    }

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Tiauth {
        pub claims: Vec<UserClaim>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Resources {
        pub resources: Vec<String>,
    }
}

async fn root_request() -> Result<impl warp::Reply, warp::Rejection> {
    let uri = "https://www.tiptenbrink.nl".parse::<warp::http::Uri>().unwrap();
    Ok(warp::redirect(uri))
}

mod params {
    use super::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub struct UserSalt {
        pub user_hex: String,
    }

    #[derive(Deserialize, Serialize)]
    pub struct UserHex {
        pub user_hex: String,
    }
}

pub async fn prepare_server() {
    files::prepare_directories().await.unwrap();
}

pub async fn run_server() {
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "trace")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    log::debug!("main debug");
    log::info!("main info");

    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type"])
        .allow_methods(vec!["POST", "GET", "OPTIONS"]);

    let user_verify = path("user_verify")
        .and(warp::get())
        .and(warp::query::<params::UserHex>())
        .and_then(login::reply_user_public);

    let register = path("register")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(register::write_user);

    let user_salt = warp::path("user_salt")
        .and(warp::get())
        .and(warp::query::<params::UserHex>())
        .and_then(login::reply_user_salt);

    let login = path("login")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(login::login_user);

    let new_claim = path("new_claim")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(claims::new_user_claim);

    let modify_claims = path("modify_claims")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(claims::modify_user_claims);

    let alive = path("alive")
        .map(|| "alive!");

    let root = path::end()
        .and(warp::get())
        .and_then(root_request);

    let routes = warp::any().and(
        register
            .or(user_salt)
            .or(login)
            .or(user_verify)
            .or(new_claim)
            .or(modify_claims)
            .or(alive)
            .or(root), )
        .recover(handle_rejection)
        .with(cors);

    warp::serve(routes).run(([0, 0, 0, 0], 3031)).await;
}

async fn handle_rejection(err: warp::reject::Rejection) -> Result<impl warp::reply::Reply, warp::Rejection> {
    #[derive(Serialize)]
    struct ErrorMessage {
        code: u16,
        message: String,
    }

    let code;
    let message: String;
    let error_str: String;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND".to_owned();
        error_str = "".to_string();
    }
    else if let Some(error_reject) = err.find::<ErrorReject>() {
        code = StatusCode::from_u16(error_reject.rt.code()).unwrap();

        // Error messages can be propagated to the requester by putting them in between '@@@' on
        // both sides.
        let split_app = error_reject.e.split("@@@").collect::<Vec<&str>>();
        let n_split = split_app.len();
        let mut msg_apps: Vec<String> = Vec::new();
        let mut err_apps: Vec<String> = Vec::new();
        if n_split % 2 == 1 {
            for (i, e) in split_app.iter().enumerate() {
                if i % 2 == 0 {
                    err_apps.push((*e).to_owned());
                }
                else {
                    msg_apps.push((*e).to_owned())
                }
            }
        }
        else {
            err_apps.push(error_reject.e.clone());
        }
        let msg_apps = msg_apps.join(" ");
        let err_apps = err_apps.join(" ");

        message = format!("{}: {} {}", error_reject.rt.name(), error_reject.msg, msg_apps);

        error_str = err_apps
    }
    else {
        eprintln!("unhandled rejection: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = format!("UNHANDLED REJ {:?}", err);
        error_str = "".to_string();
    }

    let error_message = &ErrorMessage {
        code: code.as_u16(),
        message: message.to_owned(),
    };


    let j = warp::reply::json(&error_message);

    debug!("Rejection {}: {}", code, message);
    debug!("Err: {}", error_str);

    Ok(warp::reply::with_status(j, code))
}