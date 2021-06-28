use crate::error::ErrorReject;
use crate::error::RejectTypes;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{self, AsyncWriteExt, AsyncReadExt};
use crate::defs;
use crate::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct SaveUserJson {
    pub user_hex: String,
    pub password_hash_hex: String,
    pub salt_hex: String,
    pub secret_hex: String,
    pub public_hex: String,
}

pub fn io_is_nonexistent(e: &io::Error) -> bool {
    e.raw_os_error().map_or(false, |i| {
        i == 2
    })
}

pub fn io_nonexistent_reject(e: io::Error, msg: &'static str, ne_msg: &'static str) -> ErrorReject {
    let err_msg = e.to_string();
    if io_is_nonexistent(&e) {
        ErrorReject {
            rt: RejectTypes::NonExistent,
            msg: ne_msg,
            e: err_msg
        }
    }
    else {
        ErrorReject {
            rt: RejectTypes::IO,
            msg,
            e: err_msg
        }
    }
}

pub async fn read_user(user_hex: &str, secret: bool) -> Result<SaveUserJson, io::Error> {
    let mut f = open_user_file(user_hex).await?;
    let mut buffer = String::new();
    f.read_to_string(&mut buffer).await?;

    let mut save_user: SaveUserJson = serde_json::from_str(&buffer)?;
    if !secret {
        save_user.secret_hex = "".to_owned();
        save_user.password_hash_hex = "".to_owned();
    }

    Ok(save_user)
}

pub async fn read_user_claims(user_hex: &str) -> Result<defs::Tiauth, io::Error> {
    let path = Path::new("claims/a").with_file_name(user_hex);
    let mut file = File::open(path.with_extension("json")).await?;
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).await?;

    let user_claims: defs::Tiauth = serde_json::from_str(&buffer)?;

    Ok(user_claims)
}

pub async fn register_user(user_json: &defs::UserJson, public_hex: String, secret_hex: String) -> tokio::io::Result<File> {
    let save_user_json = SaveUserJson {
        user_hex: user_json.user_hex.to_owned(),
        password_hash_hex: user_json.password_hash_hex.to_owned(),
        salt_hex: user_json.salt_hex.to_owned(),
        secret_hex,
        public_hex
    };

    let j = serde_json::to_string_pretty(&save_user_json)?;
    let path = Path::new("users/x").with_file_name(&user_json.user_hex);
    let path = path.with_extension("json");
    let mut file = File::create(path).await?;
    file.write_all(j.as_bytes()).await?;

    Ok(file)
}

pub async fn write_new_user_resource(resources_arr: Vec<String>) -> tokio::io::Result<File> {
    let new_resources = defs::Resources {
        resources: resources_arr,
    };

    let j = serde_json::to_string_pretty(&new_resources)?;
    let path = Path::new("").with_file_name("resources");
    let path = path.with_extension("json");
    let mut file = File::create(path).await?;
    file.write_all(j.as_bytes()).await?;

    Ok(file)
}

pub async fn write_user_claims(user_hex: &str, user_claims: &defs::Tiauth) -> tokio::io::Result<File> {
    let j = serde_json::to_string_pretty(user_claims)?;

    let path = Path::new("claims/a").with_file_name(user_hex);
    let mut file = File::create(path.with_extension("json")).await?;
    file.write_all(j.as_bytes()).await?;

    Ok(file)
}

pub async fn open_user_file(user_hex: &str) -> tokio::io::Result<File> {
    let path = Path::new("users/a").with_file_name(user_hex);
    let file = File::open(path.with_extension("json")).await?;

    Ok(file)
}

pub async fn open_resources() -> tokio::io::Result<defs::Resources> {
    let path = Path::new("").with_file_name("resources");
    let path = path.with_extension("json");
    let mut file = File::open(path).await?;
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).await?;

    let resources: defs::Resources = serde_json::from_str(&buffer)?;

    Ok(resources)
}