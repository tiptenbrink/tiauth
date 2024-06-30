use std::{collections::HashMap, path::Path, time::SystemTime};

use lazy_borink::Lazy;
use redb::{Database, Error as DbError, ReadableTable, TableDefinition, WriteTransaction};
use rmp_serde::{decode, encode};
use serde::{Deserialize, Serialize};
use terrors::OneOf;
use thiserror::Error;
use zerovec::{make_varule, maps::ZeroMapKV, ule::VarULE, vecs::Index32, VarZeroSlice, VarZeroVec};

use crate::{data::{BytePacked, Login, LoginPassword}, error::WrapErrorOneOf, state::State, Claims};

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

    pub fn ephemeral(&self) -> TableDefinition<'_, &'static str, &'static str> {
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
        let state_name = format!("{}:ephemeral", application);

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

#[derive(PartialEq, Eq, Debug)]
pub enum EphemeralType {
    NewUser,
    ChangePassword,
    SetPassword,
    Opaque,
}

impl EphemeralType {
    pub fn is(&self) -> impl Fn(&EphemeralType) -> bool + '_ {
        |t: &EphemeralType| t.key_name() == self.key_name()
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

pub struct EphemeralEntry {
    pub user_id: String,
    pub expires: u64,
    entropy: String,
    pub eph_type: EphemeralType,
    pub value: Option<String>,
}

impl EphemeralEntry {
    // If expires_in is set to None, it will default to 30 minutes
    pub fn new(
        user_id: &str,
        eph_type: EphemeralType,
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
            eph_type,
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
        let eph_type = split[split.len() - 3].to_owned();
        let entropy = split[split.len() - 2].to_owned();

        // 384 bits nonce, i.e. 48 bytes, 64 base64url characters, which are all 1 byte, so 64 bytes
        assert_eq!(entropy.len(), 64);

        let expires: u64 = split[split.len() - 1].parse().unwrap();

        Self {
            user_id,
            expires,
            entropy,
            eph_type: EphemeralType::from_key_name(&eph_type),
            value: None,
        }
    }

    fn with_value(self, value: &str) -> Self {
        Self {
            user_id: self.user_id,
            expires: self.expires,
            entropy: self.entropy,
            eph_type: self.eph_type,
            value: Some(value.to_owned()),
        }
    }

    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.user_id,
            self.eph_type.key_name(),
            self.entropy,
            self.expires
        )
    }
}

pub fn write_ephemeral(
    state: &impl State,
    application: &str,
    entry: EphemeralEntry,
) -> Result<(), DbError> {
    let tables = state.tables().app(application);

    let write_txn = state.db().begin_write()?;
    {
        let mut table = write_txn.open_table(tables.ephemeral())?;
        table.insert(entry.key().as_str(), entry.value.unwrap().as_str())?;
    }
    write_txn.commit()?;

    Ok(())
}

/// Reads the provided key, removing it in the process. Should be used only for ephemeral, one-time keys.
/// Do not use for keys which are supposed to represent revocations, as they will be removed, voiding the revocation.
pub fn pop_ephemeral(
    state: &impl State,
    application: &str,
    key: &str,
    allowed_types: Vec<EphemeralType>,
) -> Result<Option<EphemeralEntry>, DbError> {
    let empty_entry = EphemeralEntry::without_value(key);

    if allowed_types.iter().all(|t| *t != empty_entry.eph_type) {
        panic!("Types do no match for state!")
    }
    let tables = state.tables().app(application);
    let write_txn = state.db().begin_write()?;
    let eph_data = {
        let mut table = write_txn.open_table(tables.ephemeral())?;
        let access = table.remove(key)?;
        access.map(|d| {
            let value = d.value();

            empty_entry.with_value(value)
        })
    };
    write_txn.commit()?;

    Ok(eph_data)
}

pub fn set_login(state: &impl State, login: &Login, application: &str) -> Result<(), DbError> {
    let buf = login.serialize();
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
    claims: Option<BytePacked<Claims>>,
    options: SetLoginOptions,
) -> Result<(), OneOf<(DbError, LoginFieldError)>> {
    // One of the two must be set
    assert!(password_file.is_some() || claims.is_some());

    let tables = state.tables().app(application);
    let mut table = write_txn.open_table(tables.users()).to_one_of_two()?;

    let user_bytes = {
        let access = table.get(user_id).to_one_of_two()?;

        if let Some(access) = access {
            let user_bytes = access.value();
            let mut user: Login =  Login::deserialize(user_bytes);
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
            user.serialize()
        } else if options.create_user {
            // Password file must contain value when creating user!
            assert!(password_file.is_some());

            let login = Login {
                user_id: user_id.to_owned(),
                password_file: password_file.unwrap(),
                claims: todo!(),
                // claims: claims.unwrap_or_else(|| Claims::none().into()),
            };

            login.serialize()
        } else {
            return Err(OneOf::new(LoginFieldError::NotFound(user_id.to_owned())));
        }
    };
    
    table.insert(user_id, user_bytes.as_slice()).to_one_of_two()?;
    

    Ok(())
}

pub fn get_login(
    state: &impl State,
    application: &str,
    user_id: &str,
) -> Result<Option<LoginPassword>, DbError> {
    let read_txn = state.db().begin_read()?;
    let tables = state.tables().app(application);

    let table = read_txn.open_table(tables.users())?;

    let access = table.get(user_id)?;

    if let Some(access) = access {
        let login_bytes = access.value();

        Ok(Some(LoginPassword::deserialize_from_login(login_bytes)))
    } else {
        Ok(None)
    }
}

pub fn get_login_claims_subset_bytes<S: AsRef<str>>(
    state: &impl State,
    application: &str,
    user_id: &str,
    requested_claims: Vec<S>,
) -> Result<Option<Vec<u8>>, DbError> {
    let read_txn = state.db().begin_read()?;
    let tables = state.tables().app(application);

    let table = read_txn.open_table(tables.users())?;

    let access = table.get(user_id)?;

    if let Some(access) = access {
        let login_bytes = access.value();

        let login = Login::deserialize(login_bytes);

        Ok(Some(Vec::new()))
    } else {
        Ok(None)
    }
}


#[cfg(feature = "test")]
pub mod test_util {
    use std::sync::Arc;

    use crate::test::TestState;

    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use serde::{Deserialize, Serialize};
    use zerovec::ZeroMap;

    
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct Data<'a> {
        #[serde(borrow)]
        map: ZeroMap<'a, str, [u8]>,
    }

    // pub fn big_claims() -> (Vec<u8>, Lazy<Claims>) {
    //     let mut rng = StdRng::from_entropy();
    //     let len = 4500;
    //     let mut map: HashMap<String, Vec<u8>> = HashMap::with_capacity(len);
    //     let mut zmap: ZeroMap<'_, str, [u8]> = ZeroMap::with_capacity(len);
        
    //     for i in 0..len {
    //         let mut value_vec = Vec::with_capacity(10);
    //         for _ in 0..12 {
    //             let v = rng.next_u32();
    //             let vu = (v % 8) as u8;
    //             value_vec.push(vu)
    //         }
    //         let k = format!("{}", rng.next_u64());
    //         let k_small = k[0..8].to_string();
    //         //println!("{} yes here!", i);
    //         zmap.insert(&k_small, &value_vec);
    //         map.insert(k_small, value_vec);
    //     }
    //     //println!("got here!");
    //     let claims = Claims(map);
    //     let zmap_bytes = rmp_serde::to_vec_named(&Data { map: zmap }).unwrap();

    //     let lazy_claims = Lazy::from_inner(claims);
    //     let bytes = lazy_claims.take_bytes();
    //     (zmap_bytes, Lazy::from_bytes(bytes))
    // }

    // pub fn test_lazy_claims(state: &impl State, app: &str, mut lazy_claims: Lazy<Claims>) -> Claims {
    //     let mut rng = StdRng::from_entropy();
    //     let user_id = rng.next_u32().to_string();
    //     // let pre_login = Login {
    //     //     user_id: "hi".to_owned(),
    //     //     password_file: "pw".to_owned(),
    //     //     claims: Claims::none().into(),
    //     // };
            
    //     let tables = state.tables().app(app);
    //     let write_txn = state.db().begin_write().unwrap();
    //     {
    //         let mut table = write_txn.open_table(tables.users()).unwrap();
    //         table.insert(user_id.as_str(), lazy_claims.bytes()).unwrap();
    //     }
    //     write_txn.commit().unwrap();

    //     //set_login(state, &pre_login, app).unwrap();

    //     let read_txn = state.db().begin_read().unwrap();

    //     let table = read_txn.open_table(tables.users()).unwrap();

    //     let access = table.get(user_id.as_str()).unwrap();

    //     let access = access.unwrap();
    
    //     let _deserialized: Lazy<Claims> = Lazy::from_bytes(access.value().to_vec());
    //     let _deserialized = _deserialized.take();
        
    //     _deserialized
    // }

    // pub fn test_zero_vec(state: &impl State, app: &str, data_serial: Vec<u8>) -> Vec<u8> {
    //     let mut rng = StdRng::from_entropy();
    //     let user_id = rng.next_u32().to_string();
    //     // let pre_login = Login {
    //     //     user_id: "hi".to_owned(),
    //     //     password_file: "pw".to_owned(),
    //     //     claims: Claims::none().into(),
    //     // };
            
    //     let tables = state.tables().app(app);
    //     let write_txn = state.db().begin_write().unwrap();
    //     {
    //         let mut table = write_txn.open_table(tables.users()).unwrap();
    //         table.insert(user_id.as_str(), data_serial.as_slice()).unwrap();
    //     }
    //     write_txn.commit().unwrap();

    //     //set_login(state, &pre_login, app).unwrap();

    //     let read_txn = state.db().begin_read().unwrap();

    //     let table = read_txn.open_table(tables.users()).unwrap();

    //     let access = table.get(user_id.as_str()).unwrap();

    //     let access = access.unwrap();
    //     let access_bytes = access.value();
    
    //     let _deserialized: Data = rmp_serde::from_slice(access_bytes).unwrap();

        
        
    //     access_bytes.to_vec()
    // }
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
            claims: todo!(),
        };

        let app = "abc";

        let state = TestState::setup_test(vec![app]);

        set_login(&state, &value, app).unwrap();

        let read_login = get_login(&state, app, &value.user_id).unwrap().unwrap();

        assert_eq!(value.user_id, read_login.user_id);
        assert_eq!(value.password_file, read_login.password_file);
        //assert_eq!(value.claims.take(), read_login.claims.take());
    }
    use serde::{Deserialize, Serialize};
    use zerovec::ZeroMap;

    
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct Data<'a> {
        #[serde(borrow)]
        map: ZeroMap<'a, u32, str>,
    }


    #[test]
    fn test_zero_vec() {
        //let claims = Claims::new(vec![("claim1", "is_this"), ("claim2", "is_that"), ("claim3", "is_thatd")]);

        let pre_login = Login {
            user_id: "hi".to_owned(),
            password_file: "pw".to_owned(),
            claims: todo!(),
        };

        let mut map = ZeroMap::new();
        map.insert(&1, "one");
        map.insert(&2, "two");
        map.insert(&4, "four");
        let user_id = "3";

        let data = Data { map };

        let app = "abc";

        let state = TestState::setup_test(vec![app]);

        let bytes = rmp_serde::to_vec_named(&data).unwrap();
            
        let tables = state.tables().app(app);
        let write_txn = state.db().begin_write().unwrap();
        {
            let mut table = write_txn.open_table(tables.users()).unwrap();
            table.insert(user_id, bytes.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();

        set_login(&state, &pre_login, app).unwrap();

        let read_txn = state.db().begin_read().unwrap();

        let table = read_txn.open_table(tables.users()).unwrap();

        let access = table.get(user_id).unwrap();

        let access = access.unwrap();
        let access_bytes = access.value();
    
        let deserialized: Data = rmp_serde::from_slice(access_bytes).unwrap();

        println!("{:?}", deserialized);
    }
}
