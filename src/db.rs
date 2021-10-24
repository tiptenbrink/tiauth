use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use crate::error::{ErrorExt, TiauthError};
use crate::models::{UserAuth};


pub async fn connect() -> SqliteConnection {
    let database_url = "/tmp/tidb.sqlite";
    SqliteConnection::establish(database_url).expect("Connection error!")
}

pub async fn upsert_user(conn: SqliteConnection, user: UserAuth) -> Result<(), TiauthError>{
    use crate::schema::user_auth::dsl::*;

    diesel::replace_into(user_auth).values(
        (
            user_hex.eq(user.user_hex),
            salt_hex.eq(user.password_hash_hex),
            salt_hex.eq(user.salt_hex),
            secret_hex.eq(user.secret_hex),
            public_hex.eq(user.public_hex)
        )
    )
        .execute(&conn)
        .repl("Error upserting user")?;

    Ok(())
}