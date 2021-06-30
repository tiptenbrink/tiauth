use rusqlite::{params, Connection, Result};
use crate::error::{RejectableExt, RejectTypes, ErrorReject, RusqliteResultExt, RusqliteErrorPass};
use crate::Serialize;
use env_logger::Env;
use log::debug;

#[derive(Debug, Serialize)]
pub struct UserAuth {
    pub user_hex: String,
    pub password_hash_hex: String,
    pub salt_hex: String,
    pub secret_hex: String,
    pub public_hex: String,
}

#[derive(Debug)]
pub struct UserClaim {
    pub origin: String,
    pub anphd_id: String,
    pub uuid: String,
    pub permission: u16,
}

impl UserClaim {
    fn uri(&self) -> String {
        format!("{}--{}", self.origin, self.anphd_id)
    }

    fn claim_id(&self, user_hex: &str) -> String {
        format!("{}---{}", user_hex, self.uri())
    }
}

static AUTH_TABLE: &'static str = "user_auth";

static USER_HEX: &'static str = "user_hex";
static PASSWORD_HASH_HEX: &'static str = "password_hash_hex";
static SALT_HEX: &'static str = "salt_hex";
static SECRET_HEX: &'static str = "secret_hex";
static PUBLIC_HEX: &'static str = "public_hex";

pub fn create_auth_table(conn: &mut Connection) -> Result<()> {
    let sql_string = format!("\
        CREATE TABLE {} (
        {1} TEXT PRIMARY KEY CHECK(LENGTH({1}) < 1000),
        {2} TEXT CHECK({2} NOT NULL and LENGTH({2}) == 64),
        {3} TEXT CHECK({3} NOT NULL and LENGTH({3}) == 32),
        {4} TEXT CHECK({4} NOT NULL and LENGTH({4}) == 64),
        {5} TEXT CHECK({5} NOT NULL and LENGTH({5}) == 64)
            )",
        AUTH_TABLE, USER_HEX, PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);

    let tx = conn.transaction()?;
    match tx.execute(&sql_string, [])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

static CLAIM_ID: &'static str = "claim_id";
static CLAIMS_TABLE: &'static str = "user_claims";
static RESOURCE_URI: &'static str = "uri";
static RESOURCE_UUID: &'static str = "uuid";
static CLAIM_PERMISSION: &'static str = "permission";

pub fn create_user_claims_table(conn: &mut Connection) -> Result<()> {
    let sql_table_string = format!("\
        CREATE TABLE {table} (
        {uh_name} TEXT NOT NULL,
        {claim_id} TEXT PRIMARY KEY CHECK({claim_id} = {uh_name} || '---' || {uri}),
        {uri} TEXT NOT NULL,
        {uuid} TEXT NOT NULL,
        {permission} INTEGER NOT NULL,
        FOREIGN KEY({uri}) REFERENCES {resources_table}({uri}),
        FOREIGN KEY({uh_name}) REFERENCES {auth_table}({uh_name})
            )",
        table=CLAIMS_TABLE, uh_name=USER_HEX, claim_id=CLAIM_ID, uri=RESOURCE_URI, uuid=RESOURCE_UUID,
        permission=CLAIM_PERMISSION, resources_table=RESOURCES_TABLE, auth_table=AUTH_TABLE);

    let sql_index_string = format!("
        CREATE INDEX {uh_name}_index
        ON {table}({uh_name})",
                                   uh_name=USER_HEX, table=CLAIMS_TABLE);

    let tx = conn.transaction()?;
    match tx.execute(&sql_table_string, [])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            Ok(updated)
        },
        Err(err) => Err(err),
    }?;

    match tx.execute(&sql_index_string, [])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

static RESOURCES_TABLE: &'static str = "user_resources";
static RESOURCE_ORIGIN: &'static str = "origin";
static RESOURCE_ANPHD_ID: &'static str = "anphd_id";

pub fn create_resources_table(conn: &mut Connection) -> Result<()> {
    let sql_string = format!("\
        CREATE TABLE {table} (
        {uri} TEXT PRIMARY KEY CHECK({uri} = {origin} || '--' || {anphd_id}),
        {origin} TEXT NOT NULL,
        {anphd_id} TEXT NOT NULL
            )", table=RESOURCES_TABLE, uri=RESOURCE_URI, origin=RESOURCE_ORIGIN, anphd_id=RESOURCE_ANPHD_ID);

    let tx = conn.transaction()?;
    match tx.execute(&sql_string, [])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

/// Reads user auth data from `AUTH_TABLE`.
///
/// # Arguments
///
/// * `secret` - `bool` that tells whether to read the secret parts of the data (`PASSWORD_HASH_HEX`,
/// `SECRET_HEX`).
///
/// # Examples
///
/// Basic usage:
///
/// ```rust,no_run
/// # use tiauth::db::{read_user_auth, UserAuth};
/// # use tiauth::error::RusqliteErrorPassExt;
/// # use rusqlite::Connection;
///fn get_user_salt(conn: &Connection) -> Result<String, warp::Rejection> {
///    let user: UserAuth = read_user_auth(&conn, &user_hex, false).sql_rej("(user public)")?;
///    Ok(user.salt_hex)
/// }
/// ```
pub fn read_user_auth(conn: &Connection, user_hex: &str, secret: bool) -> Result<UserAuth, RusqliteErrorPass> {
    let columns: String;
    if !secret {
        columns = format!("{}, {}", SALT_HEX, PUBLIC_HEX);
    } else {
        columns = format!("{}, {}, {}, {}", PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);
    }
    let sql_string = format!("SELECT DISTINCT {columns} FROM {table} WHERE {uh_name}='{uh}'",
                             columns=columns, table=AUTH_TABLE, uh_name=USER_HEX, uh=user_hex);
    let user = conn.query_row(&sql_string, [], |row| {
        Ok(UserAuth {
            user_hex: user_hex.to_owned(),
            password_hash_hex: if secret { row.get(0)? } else { "".to_owned() },
            salt_hex: if !secret { row.get(0)? } else { row.get(1)? },
            secret_hex: if secret { row.get(2)? } else { "".to_owned() },
            public_hex: if !secret { row.get(1)? } else { row.get(3)? },
        })
    }).err_pass("User read query failure")?;

    Ok(user)
}

pub fn user_exists(conn: &Connection, user_hex: &str) -> Result<bool, RusqliteErrorPass> {
    let exists = key_in_column(conn, AUTH_TABLE, USER_HEX, user_hex)
        .err_pass("User exists query failure")?;

    Ok(exists)
}

fn key_in_column(conn: &Connection, table: &str, column: &str, key_value: &str) -> Result<bool> {
    let sql_string = format!("\
        SELECT EXISTS(SELECT 1 FROM {table} WHERE {column}='{value}')
    ", table=table, column=column, value=key_value);

    let exists: bool = conn.query_row(&sql_string, [], |row| Ok(row.get(0)?))?;

    Ok(exists)
}

pub fn add_user(conn: &mut Connection, user: UserAuth) -> Result<(), RusqliteErrorPass> {
    let sql_str_auth = format!("\
        INSERT INTO {} ({}, {}, {}, {}, {})
        VALUES(?1, ?2, ?3, ?4, ?5)",
        AUTH_TABLE, USER_HEX, PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);
    debug!("add user:\n{}", sql_str_auth);

    let res = conn.execute(&sql_str_auth, params![
            user.user_hex,
            user.password_hash_hex,
            user.salt_hex,
            user.secret_hex,
            user.public_hex,
        ]).err_pass("User add execute failure").and(Ok(()))?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_user_auth_test() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_auth_table(&mut conn).unwrap();
        let sql_string = format!("INSERT INTO {} ({}, {}, {}, {}, {}) VALUES(?1, ?2, ?3, ?4, ?5)",
                                 AUTH_TABLE, USER_HEX, PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);
        let mock_user = UserAuth {
            user_hex: "74-74".to_owned(),
            password_hash_hex: "54d8b194ea913a028063c3b19a7124d3dded561b1b18c760b1492a6ba717004e".to_owned(),
            salt_hex: "07b7ccb11df7581a6c06f5e2bcc85858".to_owned(),
            secret_hex: "4babbac197aebb1c87f6edb2c7a4712f65550d4f1a304dd0233b4bac834a52c0".to_owned(),
            public_hex: "7f87e14e08f036c0d3ca6f18787907b5193c2d9aadb3a93f9b39408fd2cbf5f6".to_owned(),
        };
        let res = conn.execute(&sql_string, params![
            mock_user.user_hex,
            mock_user.password_hash_hex,
            mock_user.salt_hex,
            mock_user.secret_hex,
            mock_user.public_hex,
        ]);


    }
}