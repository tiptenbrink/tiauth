#![allow(dead_code)]

use rand::rngs::StdRng;
use redb::{Database, Error as DbError, ReadableTable, TableDefinition, WriteTransaction};
use rmp_serde::{decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::Path;
use std::str;
use std::time::SystemTime;
use terrors::OneOf;
use thiserror::Error;

use crate::crypto::{self, load_public_key, PublicKey, SessionKey};
use crate::error::WrapErrorOneOf;
use crate::state::State;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Login {
    pub user_id: String,
    pub password_file: String,
    pub claims: Claims,
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
#[serde(transparent)]
#[derive(Default)]
pub struct Claims(pub HashMap<String, Vec<u8>>);

impl Claims {
    pub fn new<S, V>(map: Vec<(S, V)>) -> Self
    where
        S: Into<String>,
        V: AsRef<[u8]>,
    {
        Self(HashMap::from_iter(
            map.into_iter()
                .map(|(s, v)| (s.into(), v.as_ref().to_vec())),
        ))
    }

    /// Returns only claims with keys in the provided subset. Consumes the previous claims object.
    pub fn into_subset<S>(mut self, subset: Vec<S>) -> Self
    where
        S: AsRef<str>,
    {
        Self(HashMap::from_iter(
            subset
                .iter()
                .filter_map(|s| self.0.remove_entry(s.as_ref())),
        ))
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Session {
    pub user_id: String,
    pub application: String,
    pub issued: u64,
    pub expires: u64,
    /// These are a subset of the "login claims"
    /// They are a msgpack map
    pub session_claims: Claims,
}

impl Session {
    pub fn token(&self, session_key: &SessionKey, rng: &mut StdRng) -> Vec<u8> {
        let session_encoded = encode::to_vec_named(&self).unwrap();

        crypto::session(&session_encoded, session_key, rng)
    }
}

pub type TableStore = (String, String, String);

pub struct AppTable {
    store: TableStore,
}

impl AppTable {
    pub fn new(store: TableStore) -> Self {
        Self { store }
    }

    pub fn sessions(&self) -> TableDefinition<'_, &'static [u8], &'static str> {
        let table_name = self.store.0.as_str();

        TableDefinition::new(table_name)
    }

    pub fn users(&self) -> TableDefinition<'_, &'static str, &'static [u8]> {
        let table_name = self.store.1.as_str();

        TableDefinition::new(table_name)
    }

    pub fn state(&self) -> TableDefinition<'_, &'static str, &'static str> {
        let table_name = self.store.2.as_str();

        TableDefinition::new(table_name)
    }
}

pub trait Tables {
    fn app(&self, application: &str) -> AppTable;

    fn register_application(&mut self, application: &str);
}

#[derive(Debug)]
pub struct MapTables {
    tables: HashMap<String, TableStore>,
}

impl Default for MapTables {
    fn default() -> Self {
        Self::new()
    }
}

impl MapTables {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }
}

impl Tables for MapTables {
    fn register_application(&mut self, application: &str) {
        let session_name = format!("{}:sessions", application);
        let user_name = format!("{}:users", application);
        let state_name = format!("{}:state", application);

        self.tables.insert(
            application.to_owned(),
            (session_name, user_name, state_name),
        );
    }

    fn app(&self, application: &str) -> AppTable {
        AppTable::new(self.tables.get(application).unwrap().clone())
    }
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

    pub fn public_key(&self) -> PublicKey {
        load_public_key(&self.public_key)
    }
}

// // TODO maybe move this to start? I don't like that the DB stuff can be called at any moment
// pub fn app_key<'a>(state: impl State, app_name: &str) -> Result<&'a PublicKey, DbError> {
//     let key = state.app_keys.get(app_name);

//     if key.is_some() {
//         // This is necessary due to borrow checker limitation (see https://blog.rust-lang.org/2022/08/05/nll-by-default.html)
//         // It requires the "borrow checker of the future"
//         // Alternative is to instead return an owned PublicKey. Probably a clone is faster than a second get, but it doesn't matter much
//         // Entry API is also not an option because the below code is fallible
//         Ok(state.app_keys.get(app_name).unwrap())
//     } else {
//         let read_txn = state.db.begin_read()?;

//         let table = read_txn.open_table(APPS)?;

//         let application: Application =
//             decode::from_read(table.get(app_name)?.unwrap().value()).unwrap();

//         let public_key = load_public_key(&application.public_key);

//         state
//             .app_keys
//             .insert(app_name.to_owned(), public_key.clone());

//         Ok(state.app_keys.get(app_name).unwrap())
//     }
// }

pub fn set_login(state: &impl State, login: &Login, application: &str) -> Result<(), DbError> {
    let buf = encode::to_vec_named(login).unwrap();
    let user_id = login.user_id.as_str();
    let tables = state.tables().app(application);
    let write_txn = state.db().begin_write()?;
    {
        let mut table = write_txn.open_table(tables.users())?;
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
    state: &impl State,
    application: &str,
    user_id: &str,
    password_file: Option<String>,
    claims: Option<Claims>,
    options: SetLoginOptions,
) -> Result<(), OneOf<(DbError, LoginFieldError)>> {
    // One of the two must be set
    assert!(password_file.is_some() || claims.is_some());

    let tables = state.tables().app(application);
    let mut table = write_txn.open_table(tables.users()).to_one_of_two()?;
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

pub fn get_login(
    state: &impl State,
    application: &str,
    user_id: &str,
) -> Result<Option<Login>, DbError> {
    let read_txn = state.db().begin_read()?;
    let tables = state.tables().app(application);

    let table = read_txn.open_table(tables.users())?;

    let access = table.get(user_id)?;

    Ok(access.map(|a| decode::from_read(a.value()).unwrap()))
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

pub fn write_state(
    state: &impl State,
    application: &str,
    entry: StateEntry,
) -> Result<(), DbError> {
    let tables = state.tables().app(application);

    let write_txn = state.db().begin_write()?;
    {
        let mut table = write_txn.open_table(tables.state())?;
        table.insert(entry.key().as_str(), entry.value.unwrap().as_str())?;
    }
    write_txn.commit()?;

    Ok(())
}

/// Reads the provided key, removing it in the process. Should be used only for ephemeral, one-time keys.
/// Do not use for keys which are supposed to represent revocations, as they will be removed, voiding the revocation.
pub fn pop_state(
    state: &impl State,
    application: &str,
    key: &str,
    allowed_types: Vec<StateType>,
) -> Result<Option<StateEntry>, DbError> {
    let empty_entry = StateEntry::without_value(key);

    if allowed_types.iter().all(|t| *t != empty_entry.state_type) {
        panic!("Types do no match for state!")
    }
    let tables = state.tables().app(application);
    let write_txn = state.db().begin_write()?;
    let state_data = {
        let mut table = write_txn.open_table(tables.state())?;
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
    use super::*;
    use crate::data::Login;
    use crate::state::test_util::*;

    #[test]
    fn login_set_read() {
        let value = Login {
            user_id: "hi".to_owned(),
            password_file: "pw".to_owned(),
            claims: Claims::default(),
        };

        let app = "abc";

        let state = TestState::setup_test(vec![app]);

        set_login(&state, &value, app).unwrap();

        let read_login = get_login(&state, app, &value.user_id).unwrap().unwrap();

        assert_eq!(value.user_id, read_login.user_id);
        assert_eq!(value.password_file, read_login.password_file);
        assert_eq!(value.claims, read_login.claims);
    }
}
