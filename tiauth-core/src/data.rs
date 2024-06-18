#![allow(dead_code)]

use redb::{Database, Error as DbError, ReadableTable, TableDefinition, WriteTransaction};
use rmp_serde::{decode, encode};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::path::Path;
use std::str;
use std::time::SystemTime;
use terrors::OneOf;
use thiserror::Error;

use crate::crypto::{load_public_key, PublicKey};
use crate::error::WrapErrorOneOf;
use crate::state::State;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Login {
    pub user_id: String,
    pub password_file: String,
    pub claims: Claims,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Claims {
    claims: Value,
}

impl Claims {
    pub fn new<S, V>(map: Vec<(S, V)>) -> Self
    where
        S: Into<String>,
        V: Into<Value>,
    {
        let value_value_map: Vec<(Value, Value)> = map
            .into_iter()
            .map(|(k, v)| {
                let s: String = k.into();
                (Value::String(s.into()), v.into())
            })
            .collect();

        Self {
            claims: Value::Map(value_value_map),
        }
    }

    /// Returns only claims with keys in the provided subset. Consumes the previous claims object.
    pub fn into_subset(self, mut subset: HashSet<&str>) -> Self {
        let claims_subset: Vec<(Value, Value)> = if let Value::Map(entries) = self.claims {
            entries
                .into_iter()
                .filter(|(key, _value)| {
                    if let Value::String(key) = key {
                        if key.is_err() {
                            panic!("Keys must be valid UTF-8!")
                        }

                        let key = key.as_str().unwrap();

                        subset.remove(key)
                    } else {
                        panic!("All claims must be string keys!")
                    }
                })
                .collect()
        } else {
            panic!("Claims must be a map type!");
        };

        Self {
            claims: Value::Map(claims_subset),
        }
    }

    pub fn get(self) -> Vec<(Value, Value)> {
        if let Value::Map(entries) = self.claims {
            entries
        } else {
            panic!("Claims must be a map type!");
        }
    }
}

impl Default for Claims {
    fn default() -> Self {
        Self {
            claims: Value::Map(Vec::new()),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Session {
    pub user_id: String,
    pub application: String,
    pub expires: u64,
    /// These are a subset of the "login claims"
    /// They are a msgpack map
    pub session_claims: Claims,
}

// #[derive(Debug, PartialEq, Deserialize, Serialize)]
// struct SignedSession {
//     #[serde(with = "serde_bytes")]
//     pub session_encoded: Vec<u8>,

//     #[serde(with = "serde_bytes")]
//     pub signature: Vec<u8>,
// }

pub fn session_table<'a>(
    tables: &'a mut HashMap<String, String>,
    application: &str,
) -> TableDefinition<'a, &'static [u8], &'static str> {
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

pub fn open_db<P: AsRef<Path>>(path: P) -> Result<Database, DbError> {
    Ok(Database::create(path)?)
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

impl Application {
    pub fn new(public_key_pem: String, name: &str) -> Self {
        Self {
            public_key: public_key_pem,
            name: name.to_owned(),
        }
    }
}

// TODO maybe move this to start? I don't like that the DB stuff can be called at any moment
pub fn app_key<'a>(state: &'a mut State, app_name: &str) -> Result<&'a PublicKey, DbError> {
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

pub fn set_login(state: &mut State, login: &Login, application: &str) -> Result<(), DbError> {
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

#[derive(Error, Debug)]
pub enum LoginFieldError {
    #[error("Could not set login: user {0} already exists.")]
    AlreadyExists(String),
    #[error("Could not set login: user {0} does not exist.")]
    NotFound(String),
    #[error("Could not set password for user {0}: already set.")]
    PasswordSet(String),
}

// /// Assumes a user has already been created. If `require_unset_password` is set to false, it will change it even if the password file is non-empty.
// /// Returns true if password was written.
// pub fn set_login_field(
//     state: &mut State,
//     application: &str,
//     user_id: &str,
//     password_file: String,
//     require_unset_password: bool,
// ) -> Result<bool, OneOf<(DbError, LoginFieldError)>> {
//     let write_txn = state.db.begin_write()?;

//     let result = set_login_field_write(
//         &write_txn,
//         state,
//         application,
//         user_id,
//         password_file,
//         require_unset_password,
//     )?;

//     write_txn.commit()?;

//     Ok(result)
// }

pub struct SetLoginOptions {
    require_unset_password: bool,
    create_user: bool,
}

impl SetLoginOptions {
    pub fn new(require_unset_password: bool, create_user: bool) -> Self {
        Self {
            require_unset_password,
            create_user,
        }
    }
}

/// Assumes "Claims" are a valid string-value map. It asserts only the map.
/// If `require_unset_password` is set to false, it returns a [LoginFieldError::PasswordSet] when password is already set.
/// If `create_user` is set to true, it will create a user when the user does not exist. Otherwise, it
/// will return a [LoginFieldError::AlreadyExists]. When set to false, it will instead return [LoginFieldError::NotFound]
/// when the user does not exist.
pub fn set_login_field_write(
    write_txn: &WriteTransaction,
    state: &mut State,
    application: &str,
    user_id: &str,
    password_file: Option<String>,
    claims: Option<Claims>,
    options: SetLoginOptions,
) -> Result<(), OneOf<(DbError, LoginFieldError)>> {
    // One of the two must be set
    assert!(password_file.is_some() || claims.is_some());

    let table_def = user_table(state.tables, application);
    let mut table = write_txn.open_table(table_def).to_one_of_two()?;
    let access = table.get(user_id).to_one_of_two()?;
    let user: Option<Login> = access.map(|a| decode::from_read(a.value()).unwrap());

    if let Some(mut user) = user {
        if options.create_user {
            return Err(OneOf::new(LoginFieldError::AlreadyExists(
                user_id.to_owned(),
            )));
        }
        if options.require_unset_password && !user.password_file.is_empty() {
            return Err(OneOf::new(LoginFieldError::PasswordSet(user_id.to_owned())));
        }

        if let Some(password_file) = password_file {
            user.password_file = password_file;
        }
        if let Some(claims) = claims {
            user.claims = claims;
        }

        let buf = encode::to_vec_named(&user).unwrap();
        table.insert(user_id, buf.as_slice()).to_one_of_two()?;
    } else if options.create_user {
        // Password file must contain value when creating user!
        assert!(password_file.is_some());

        let login = Login {
            user_id: user_id.to_owned(),
            password_file: password_file.unwrap(),
            claims: claims.unwrap_or_default(),
        };

        let buf = encode::to_vec_named(&login).unwrap();

        table.insert(user_id, buf.as_slice()).to_one_of_two()?;
    } else {
        return Err(OneOf::new(LoginFieldError::NotFound(user_id.to_owned())));
    }

    Ok(())
}

pub fn get_login(state: &mut State, application: &str, user_id: &str) -> Result<Login, DbError> {
    let read_txn = state.db.begin_read()?;
    let table_def = user_table(state.tables, application);

    let table = read_txn.open_table(table_def)?;

    Ok(decode::from_read(table.get(user_id)?.unwrap().value()).unwrap())
}

#[derive(PartialEq, Eq, Debug)]
pub enum StateType {
    NewUser,
    ChangePassword,
    SetPassword,
    Opaque,
}

impl StateType {
    pub fn is(&self) -> impl Fn(&StateType) -> bool + '_ {
        |t: &StateType| t.key_name() == self.key_name()
    }

    fn key_name(&self) -> &'static str {
        match self {
            Self::NewUser => "new_user",
            Self::ChangePassword => "change_pass",
            Self::SetPassword => "set_pass",
            Self::Opaque => "opaque",
        }
    }

    fn from_key_name(key_name: &str) -> Self {
        match key_name {
            "new_user" => Self::NewUser,
            "change_pass" => Self::ChangePassword,
            "set_pass" => Self::SetPassword,
            "opaque" => Self::Opaque,
            _ => panic!("Invalid key_name for state type!"),
        }
    }
}

pub struct StateEntry {
    pub user_id: String,
    pub expires: u64,
    entropy: String,
    pub state_type: StateType,
    pub value: Option<String>,
}

impl StateEntry {
    // If expires_in is set to None, it will default to 30 minutes
    pub fn new(
        user_id: &str,
        state_type: StateType,
        entropy: String,
        expires_in: Option<u64>,
        value: String,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = expires_in.unwrap_or(1800) + now;

        Self {
            user_id: user_id.into(),
            entropy,
            state_type,
            expires,
            value: Some(value),
        }
    }

    fn without_value(key: &str) -> Self {
        let split: Vec<&str> = key.split(':').collect();

        if split.len() < 4 {
            panic!("Entry does not have correct format!")
        }

        let user_id = split[0..(split.len() - 3)].join(":");
        let state_type = split[split.len() - 3].to_owned();
        let entropy = split[split.len() - 2].to_owned();

        // 384 bits nonce, i.e. 48 bytes, 64 base64url characters, which are all 1 byte, so 64 bytes
        assert_eq!(entropy.len(), 64);

        let expires: u64 = split[split.len() - 1].parse().unwrap();

        Self {
            user_id,
            expires,
            entropy,
            state_type: StateType::from_key_name(&state_type),
            value: None,
        }
    }

    fn with_value(self, value: &str) -> Self {
        Self {
            user_id: self.user_id,
            expires: self.expires,
            entropy: self.entropy,
            state_type: self.state_type,
            value: Some(value.to_owned()),
        }
    }

    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.user_id,
            self.state_type.key_name(),
            self.entropy,
            self.expires
        )
    }
}

pub fn write_state(state: &mut State, application: &str, entry: StateEntry) -> Result<(), DbError> {
    let table_def = state_table(state.tables, application);

    let write_txn = state.db.begin_write()?;
    {
        let mut table = write_txn.open_table(table_def)?;
        table.insert(entry.key().as_str(), entry.value.unwrap().as_str())?;
    }
    write_txn.commit()?;

    Ok(())
}

/// Reads the provided key, removing it in the process. Should be used only for ephemeral, one-time keys.
/// Do not use for keys which are supposed to represent revocations, as they will be removed, voiding the revocation.
pub fn pop_state(
    state: &mut State,
    application: &str,
    key: &str,
    allowed_types: Vec<StateType>,
) -> Result<Option<StateEntry>, DbError> {
    let empty_entry = StateEntry::without_value(key);

    if allowed_types.iter().all(|t| *t != empty_entry.state_type) {
        panic!("Types do no match for state!")
    }

    let table_def = state_table(state.tables, application);
    let write_txn = state.db.begin_write()?;
    let state_data = {
        let mut table = write_txn.open_table(table_def)?;
        let access = table.remove(key)?;
        access.map(|d| {
            let value = d.value();

            empty_entry.with_value(value)
        })
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
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let value = Login {
            user_id: "hi".to_owned(),
            password_file: "pw".to_owned(),
            claims: Claims::default(),
        };

        let app = "abc".to_owned();

        set_login(&mut state, &value, &app).unwrap();

        let read_login = get_login(&mut state, &app, &value.user_id).unwrap();

        assert_eq!(value.user_id, read_login.user_id);
        assert_eq!(value.password_file, read_login.password_file);
        assert_eq!(value.claims, read_login.claims);
    }
}
