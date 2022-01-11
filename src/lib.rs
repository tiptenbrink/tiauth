use env_logger::Env;
use log::debug;
use serde::{Deserialize, Serialize};
use warp::Filter;
use warp::path;
use warp::reject::custom as reject;

pub mod files;
pub mod error;
pub mod claims;
pub mod login;
pub mod auth;
pub mod register;
pub mod db;

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

// async fn root_request() -> Result<impl warp::Reply, warp::Rejection> {
//     let uri = "https://www.tiptenbrink.nl".parse::<warp::http::Uri>().unwrap();
//     Ok(warp::redirect(uri))
// }

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
        .filter_or("MY_LOG_LEVEL", "debug")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    log::debug!("main debug");
    log::info!("main info");

    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type"])
        .allow_methods(vec!["POST", "GET"]);

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
        .map(|| "Tiauth Authentication Server");
        // .and(warp::get())
        // .and_then(root_request);

    let routes = warp::any().and(
        register
            .or(user_salt)
            .or(login)
            .or(user_verify)
            .or(new_claim)
            .or(modify_claims)
            .or(alive)
            .or(root), )
        .recover(error::handle_err_reject)
        .recover(error::handle_reject)
        .with(cors);

    warp::serve(routes).run(([0, 0, 0, 0], 3031)).await;
}