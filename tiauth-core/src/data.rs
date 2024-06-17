#![allow(dead_code)]

use redb::{Database, Error, ReadableTable, TableDefinition, WriteTransaction};
use rmp_serde::{decode, encode};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::str;

use crate::crypto::{load_public_key, PublicKey};
use crate::state::State;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Login {
    pub user_id: String,
    pub password_file: String,
    pub claims: Value,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Session {
    pub user_id: String,
    pub expires: u64,
    /// These are a subset of the "login claims"
    /// They are a msgpack map
    pub session_claims: Value,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct SignedSession {
    #[serde(with = "serde_bytes")]
    pub session_encoded: Vec<u8>,

    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

pub fn session_table<'a>(
    tables: &'a mut HashMap<String, String>,
    application: &str,
) -> TableDefinition<'a, &'static str, &'static [u8]> {
    let table_name = tables
        .entry(format!("{}:sessions", application))
        .or_insert_with(|| format!("{}:sessions", application));

    TableDefinition::new(table_name)
}

pub fn user_table<'a>(
    tables: &'a mut HashMap<String, String>,
    application: &str,
) -> TableDefinition<'a, &'static str, &'static [u8]> {
    let table_name = tables
        .entry(format!("{}:users", application))
        .or_insert_with(|| format!("{}:users", application));

    TableDefinition::new(table_name)
}

pub fn state_table<'a>(
    tables: &'a mut HashMap<String, String>,
    application: &str,
) -> TableDefinition<'a, &'static str, &'static str> {
    let table_name = tables
        .entry(format!("{}:state", application))
        .or_insert_with(|| format!("{}:state", application));
    TableDefinition::new(table_name)
}

pub fn open_db() -> Result<Database, Error> {
    Ok(Database::create("my_db.redb")?)
}

/// Persistent server data, such as OPAQUE private key
pub const SERVER: TableDefinition<&str, String> = TableDefinition::new("server");

/// App identities
pub const APPS: TableDefinition<&str, &[u8]> = TableDefinition::new("apps");

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Application {
    // This must be a
    public_key: String,
    pub name: String,
}

// TODO maybe move this to start? I don't like that the DB stuff can be called at any moment
pub fn app_key<'a>(state: &'a mut State, app_name: &str) -> Result<&'a PublicKey, Error> {
    let key = state.app_keys.get(app_name);

    if key.is_some() {
        // This is necessary due to borrow checker limitation (see https://blog.rust-lang.org/2022/08/05/nll-by-default.html)
        // It requires the "borrow checker of the future"
        // Alternative is to instead return an owned PublicKey. Probably a clone is faster than a second get, but it doesn't matter much
        // Entry API is also not an option because the below code is fallible
        Ok(state.app_keys.get(app_name).unwrap())
    } else {
        let read_txn = state.db.begin_read()?;

        let table = read_txn.open_table(APPS)?;

        let application: Application =
            decode::from_read(table.get(app_name)?.unwrap().value()).unwrap();

        let public_key = load_public_key(&application.public_key);

        state
            .app_keys
            .insert(app_name.to_owned(), public_key.clone());

        Ok(state.app_keys.get(app_name).unwrap())
    }
}

pub fn set_login(state: &mut State, login: &Login, application: &str) -> Result<(), Error> {
    let buf = encode::to_vec_named(login).unwrap();
    let user_id = login.user_id.as_str();
    let table_def = user_table(state.tables, application);
    let write_txn = state.db.begin_write()?;

    {
        let mut table = write_txn.open_table(table_def)?;
        table.insert(user_id, buf.as_slice())?;
    }
    write_txn.commit()?;

    Ok(())
}

/// Assumes a user has already been created. If `require_unset_password` is set to false, it will change it even if the password file is non-empty.
/// Returns true if password was written.
pub fn set_login_field(
    state: &mut State,
    application: &str,
    user_id: &str,
    password_file: String,
    require_unset_password: bool,
) -> Result<bool, Error> {
    let write_txn = state.db.begin_write()?;

    let result = set_login_field_write(
        &write_txn,
        state,
        application,
        user_id,
        password_file,
        require_unset_password,
    )?;

    write_txn.commit()?;

    Ok(result)
}

/// Assumes a user has already been created. If `require_unset_password` is set to false, it will change it even if the password file is non-empty.
/// Returns true if password was written.
pub fn set_login_field_write(
    write_txn: &WriteTransaction,
    state: &mut State,
    application: &str,
    user_id: &str,
    password_file: String,
    require_unset_password: bool,
) -> Result<bool, Error> {
    let table_def = user_table(state.tables, application);
    let mut table = write_txn.open_table(table_def)?;
    let mut login: Login = decode::from_read(table.get(user_id)?.unwrap().value()).unwrap();

    if require_unset_password && !login.password_file.is_empty() {
        return Ok(false);
    }

    login.password_file = password_file;

    let buf = encode::to_vec_named(&login).unwrap();
    table.insert(user_id, buf.as_slice())?;

    Ok(true)
}

pub fn get_login(state: &mut State, application: &str, user_id: &str) -> Result<Login, Error> {
    let read_txn = state.db.begin_read()?;
    let table_def = user_table(state.tables, application);

    let table = read_txn.open_table(table_def)?;

    Ok(decode::from_read(table.get(user_id)?.unwrap().value()).unwrap())
}

pub fn write_state(
    state: &mut State,
    application: &str,
    key: &str,
    state_data: &str,
) -> Result<(), Error> {
    let table_def = state_table(state.tables, application);

    let write_txn = state.db.begin_write()?;
    {
        let mut table = write_txn.open_table(table_def)?;
        table.insert(key, state_data)?;
    }
    write_txn.commit()?;

    Ok(())
}

pub fn read_state(state: &mut State, application: &str, key: &str) -> Result<String, Error> {
    let table_def = state_table(state.tables, application);
    let write_txn = state.db.begin_write()?;
    let state_data = {
        let mut table = write_txn.open_table(table_def)?;
        let accesss = table.remove(key)?.unwrap();
        let value = accesss.value();
        value.to_owned()
    };
    write_txn.commit()?;

    Ok(state_data)
}

#[cfg(test)]
mod tests {
    use crate::{data::Login, state::StateOwner};

    use super::*;

    #[test]
    fn login_set_read() {
        let mut state_owner = StateOwner::setup().unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let value = Login {
            user_id: "hi".to_owned(),
            password_file: "pw".to_owned(),
            claims: Value::Map(Vec::new()),
        };

        let app = "abc".to_owned();

        set_login(&mut state, &value, &app).unwrap();

        let read_login = get_login(&mut state, &app, &value.user_id).unwrap();

        assert_eq!(value.user_id, read_login.user_id);
        assert_eq!(value.password_file, read_login.password_file);
        assert_eq!(value.claims, read_login.claims);
    }
}
