use std::path::{PathBuf};
use diesel::prelude::*;
use tiauth;
use tiauth::files;
use tiauth::files::SaveUserJson;
use tokio::fs;
use tokio::io::{Error, ErrorKind};

#[tokio::main]
async fn main() {
    let x = get_user_auth().await.unwrap();

    let connection = tiauth::db::connect().await;

    for user_auth in x {

    }


}

async fn get_user_auth() -> Result<Vec<SaveUserJson>, Error> {
    let mut paths = fs::read_dir("resources/users").await?;

    let mut v: Vec<SaveUserJson> = Vec::new();

    while let Some(entry) = paths.next_entry().await? {
        let e = entry.file_name().into_string()
            .map_err(|_e| Error::new(ErrorKind::Other, "OsString conversion failed."))?;

        if e.ends_with(".json") {
            if let Some(user_hex) = e.strip_suffix(".json") {
                let user = files::read_user(user_hex, true).await?;
                v.push(user);
            }

        }
    }

    Ok(v)
}