// use sqlx::sqlite::SqlitePoolOptions;
// use sqlx::prelude::*;
// use crate::error::{Error, ErrorExt};
//
// static AUTH_TABLE: &'static str = "user_auth";
//
// static USER_HEX: &'static str = "user_hex";
// static PASSWORD_HASH_HEX: &'static str = "password_hash_hex";
// static SALT_HEX: &'static str = "salt_hex";
// static SECRET_HEX: &'static str = "secret_hex";
// static PUBLIC_HEX: &'static str = "public_hex";
//
// #[derive(FromRow, Debug)]
// struct UserAuth {
//     user_hex: String,
//     password_hash_hex: String,
//     salt_hex: String,
//     secret_hex: String,
//     public_hex: String,
// }
//
// async fn connect_test() -> Result<(), Error> {
//     let pool = SqlitePoolOptions::new()
//         .max_connections(2)
//         .connect("sqlite:/tmp/tidb.sqlite").await.repl("Failed DB connection.")?;
//
//     // let columns: String;
//     // let secret = true;
//     // if !secret {
//     //     columns = format!("{}, {}", SALT_HEX, PUBLIC_HEX);
//     // } else {
//     //     columns = format!("{}, {}, {}, {}", PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);
//     // }
//     // let sql_string = format!("SELECT DISTINCT {columns} FROM {table} WHERE {uh_name}='{uh}'",
//     //                          columns=columns, table=AUTH_TABLE, uh_name=USER_HEX, uh=user_hex);
//
//     let user_auths = sqlx::query_as::<_, UserAuth>(
//         "\
// SELECT * FROM user_auth
//     \
//     ").fetch_all(&pool).await.repl("db")?;
//     println!("{:?}", user_auths);
//
//     Ok(())
// }