use camino::{Utf8Path, Utf8PathBuf};
use redb::{
    AccessGuard, CommitError, Database, Error as DbError, Key, ReadOnlyTable, ReadTransaction,
    ReadableTable as DbReadableTable, StorageError, Table, TableDefinition, TableError,
    TransactionError, Value, WriteTransaction,
};
use sha2::Digest;
use std::{
    borrow::Borrow, fmt::Display, fs, num::ParseIntError, ops::RangeBounds, path::Path,
    string::FromUtf8Error,
};
use thiserror::Error;

use crate::{
    crypto::KeyError,
    data::{empty_claim_bytes, ByteOwned, ByteSerial, SessionClaims},
    Claims,
};

// pub type TableStore = (String, String, String);

// pub struct AppTable<'a> {
//     store: &'a TableStore,
// }

// impl<'a> AppTable<'a> {
//     pub fn new(store: &'a TableStore) -> Self {
//         Self { store }
//     }

//     pub fn sessions(&self) -> TableDefinition<'_, &'static [u8], &'static str> {
//         let table_name = &self.store.0;

//         TableDefinition::new(table_name)
//     }

//     pub fn users(&self) -> TableDefinition<'_, &'static str, &'static [u8]> {
//         let table_name = &self.store.1;

//         TableDefinition::new(table_name)
//     }

//     pub fn ephemeral(&self) -> TableDefinition<'_, &'static str, &'static str> {
//         let table_name = &self.store.2;

//         TableDefinition::new(table_name)
//     }

//     pub fn all(&self) -> Vec<String> {
//         let store = self.store.clone();
//         vec![store.0, store.1, store.2]
//     }
// }

// pub trait Tables {
//     fn app(&self, application: &str) -> AppTable;
// }

// #[derive(Debug, Clone)]
// pub struct MapTables {
//     tables: HashMap<String, TableStore>,
// }

// impl Default for MapTables {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// impl MapTables {
//     pub fn new() -> Self {
//         Self {
//             tables: HashMap::new(),
//         }
//     }
// }

// impl Tables for MapTables {
//     fn app(&self, application: &str) -> AppTable {
//         let store = self.tables.get(application).unwrap();
//         AppTable::new(store)
//     }
// }

fn open_db<P: AsRef<Path>>(path: P) -> std::result::Result<Database, DbError> {
    Ok(Database::create(path)?)
}

/// Persistent server data, such as OPAQUE private key
pub const SERVER: TableDefinition<&str, String> = TableDefinition::new("server");

/// App identities
pub const APPS: TableDefinition<&str, &[u8]> = TableDefinition::new("apps");

#[derive(Debug)]
struct LoadContext {
    address: String,
    inner: String,
}

#[derive(Debug)]
struct InnerStringContext {
    inner: String,
}

#[derive(Debug)]
struct DataDeserializationContext {
    info: String,
    inner: String,
}

type StringContext = Context<InnerStringContext>;

#[derive(Error, Debug)]
pub enum DataDeserializationErrorSource {
    #[error("{0}")]
    InvalidUtf8(#[from] FromUtf8Error),
    #[error("{0}")]
    InvalidKey(#[from] KeyError),
    #[error("Tryed to coerce to specific length but failed. Expected: {exp}. Got: {got}")]
    InvalidLength { exp: usize, got: usize },
    // Generic parsing error
    #[error("Parse failure.")]
    ParseError,
}

impl From<ParseIntError> for DataDeserializationErrorSource {
    fn from(_: ParseIntError) -> Self {
        DataDeserializationErrorSource::ParseError
    }
}

#[derive(Error, Debug)]
#[error("Failed to deserialize table data: {info}. Underlying error: {kind}")]
pub struct DataDeserializationError {
    info: String,
    kind: DataDeserializationErrorSource,
}

// impl From<FromUtf8Error> for DataDeserializationError {
//     fn from(value: FromUtf8Error) -> Self {
//         Self::InvalidUtf8(Box::new(InnerStringContext { inner: value.to_string() }))
//     }
// }

pub trait WrapDeserializationError<T> {
    fn to_deser_err<S: Into<String>>(self, info: S) -> Result<T, DataDeserializationError>;
}

impl<T, E> WrapDeserializationError<T> for Result<T, E>
where
    E: Into<DataDeserializationErrorSource>,
{
    fn to_deser_err<S: Into<String>>(self, info: S) -> Result<T, DataDeserializationError> {
        match self {
            Ok(ok) => Ok(ok),
            Err(err) => Err(DataDeserializationError {
                info: info.into(),
                kind: err.into(),
            }),
        }
    }
}

pub trait WrapVecTryFromError<T> {
    fn to_deser_err<S: Into<String>>(
        self,
        exp: usize,
        info: S,
    ) -> Result<T, DataDeserializationError>;
}

impl<T, U> WrapVecTryFromError<T> for Result<T, Vec<U>> {
    fn to_deser_err<S: Into<String>>(
        self,
        exp: usize,
        info: S,
    ) -> Result<T, DataDeserializationError> {
        match self {
            Ok(ok) => Ok(ok),
            Err(err) => Err(DataDeserializationError {
                info: info.into(),
                kind: DataDeserializationErrorSource::InvalidLength {
                    exp,
                    got: err.len(),
                },
            }),
        }
    }
}

#[derive(Debug)]
#[repr(transparent)]
struct Context<T> {
    b: Box<T>,
}

impl<T> Context<T> {
    fn new(inner: T) -> Self {
        Self { b: Box::new(inner) }
    }
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Failed to load database at address {} due to underlying error: {}", .0.b.address, .0.b.inner)]
    Load(Context<LoadContext>),
    #[error("Failed to open transaction due to underlying error: {}", .0.b.inner)]
    OpenTransaction(StringContext),
    #[error("Failed to open table due to error: {}", .0.b.inner)]
    Table(StringContext),
    #[error("Failed to perform action due to underlying storage error: {}", .0.b.inner)]
    Storage(StringContext),
    #[error("{}", .0.b)]
    DataDeserialization(Context<DataDeserializationError>),
    #[error("Invariant failed to hold during initialization: {}", .0.b.inner)]
    Init(StringContext),
}

impl StoreError {
    pub fn new_init<S: Into<String>>(failed_invariant: S) -> Self {
        Self::Init(Context::new(InnerStringContext {
            inner: failed_invariant.into(),
        }))
    }
}

impl From<DataDeserializationError> for StoreError {
    fn from(value: DataDeserializationError) -> Self {
        Self::DataDeserialization(Context::new(value))
    }
}

impl From<TransactionError> for StoreError {
    fn from(value: TransactionError) -> Self {
        Self::OpenTransaction(Context::new(InnerStringContext {
            inner: value.to_string(),
        }))
    }
}

impl From<CommitError> for StoreError {
    fn from(value: CommitError) -> Self {
        Self::Storage(Context::new(InnerStringContext {
            inner: value.to_string(),
        }))
    }
}

impl From<StorageError> for StoreError {
    fn from(value: StorageError) -> Self {
        Self::Storage(Context::new(InnerStringContext {
            inner: value.to_string(),
        }))
    }
}

impl From<TableError> for StoreError {
    fn from(value: TableError) -> Self {
        match value {
            TableError::Storage(value) => Self::Storage(Context::new(InnerStringContext {
                inner: value.to_string(),
            })),
            _ => Self::Table(Context::new(InnerStringContext {
                inner: value.to_string(),
            })),
        }
    }
}

pub struct Store {
    address: StoreAddress,
    database: Database,
}

pub enum StoreType {
    Application,
    Server,
}

impl Store {
    pub fn load(address: StoreAddress, store_type: StoreType) -> Result<Self, StoreError> {
        let db = open_db(&address.0).map_err(|e| {
            StoreError::Load(Context::new(LoadContext {
                address: address.to_string(),
                inner: e.to_string(),
            }))
        })?;

        let tx = db.begin_write()?;

        match store_type {
            StoreType::Application => {
                tx.open_table(SESSIONS)?;
                tx.open_table(SESSIONS_EXPIRY)?;
                tx.open_table(CLAIMS)?;
                tx.open_table(USERS)?;
            }
            StoreType::Server => todo!(),
        }

        tx.commit()?;

        Ok(Self {
            address,
            database: db,
        })
    }

    pub fn open_read(&self) -> Result<ReadTx, StoreError> {
        let tx = self.database.begin_read()?;

        Ok(ReadTx {
            tx,
            // token: TxToken::new(),
            // tables: TxTables::default()
        })
    }

    pub fn open_write(&self) -> Result<WriteTx, StoreError> {
        let tx = self.database.begin_write()?;

        Ok(WriteTx {
            tx,
            // token: TxToken::new(),
            // tables: TxTables::default()
        })
    }

    pub fn address(&self) -> &StoreAddress {
        &self.address
    }
}

#[derive(Clone)]
pub struct StoreAddress(Utf8PathBuf);

impl StoreAddress {
    pub fn from_path<P: AsRef<Utf8Path>>(p: P) -> Self {
        let path = p.as_ref().to_path_buf();
        Self(path)
    }

    pub fn join_name(&self, name: &str) -> Self {
        let file_stem = self.0.file_stem().unwrap();
        let file_suffix = self.0.file_name().unwrap().strip_prefix(file_stem).unwrap();
        let new_file_name = format!("{}.{}.{}", file_stem, name, file_suffix);
        let new_path = match self.0.parent() {
            Some(parent) => parent.join(new_file_name),
            None => Utf8PathBuf::from(new_file_name),
        };
        Self(new_path)
    }

    pub fn destroy(&self) {
        fs::remove_file(&self.0).unwrap()
    }
}

impl Display for StoreAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

type KeysK = &'static str;
type KeysV = &'static [u8];
type KeysVOwned = Vec<u8>;
pub const KEYS: TableDefinition<KeysK, KeysV> = TableDefinition::new("keys");

pub struct KeysTableType;

impl TableType for KeysTableType {
    type Key = KeysK;
    type Value = KeysV;
}

type SessionsK = &'static [u8; 64];
type SessionsV = (u8, u64);
type SessionsExpiryK = u64;
type SessionsExpiryV = &'static [u8; 64];

//type SessionsVOwned = Vec<u8>;
// Revoked sessions
pub const SESSIONS: TableDefinition<SessionsK, SessionsV> = TableDefinition::new("sessions");
pub const SESSIONS_EXPIRY: TableDefinition<SessionsExpiryK, SessionsExpiryV> =
    TableDefinition::new("sessions_expiry");

pub struct SessionsTableType;

impl TableType for SessionsTableType {
    type Key = SessionsK;
    type Value = SessionsV;
}

pub struct SessionsExpiryTableType;

impl TableType for SessionsExpiryTableType {
    type Key = SessionsExpiryK;
    type Value = SessionsExpiryV;
}
// use tx::{TxToken, WriteTx}

// struct KeysTable<'tx>(Table<'tx, KeysK, KeysV>);

// mod tx {
//     use std::marker::PhantomData;
//     use super::{Result, TxTable};

//     struct TxGuard;

//     pub struct TxToken<'tx> {
//         phantom: PhantomData<&'tx TxGuard>
//     }

//     impl<'tx> TxToken<'tx> {
//         fn new() -> Self {
//             Self {
//                 phantom: PhantomData
//             }
//         }
//     }

// }

pub struct ReadTx {
    tx: ReadTransaction,
    // token: TxToken<'tx>,
    // tables: TxTables<'tx>
}

impl ReadTx {
    pub fn sessions_table(&self) -> Result<ReadTable<SessionsTableType>, StoreError> {
        Ok(ReadTable {
            table: self.tx.open_table(SESSIONS)?,
        })
    }

    pub fn sessions_expiry_table(&self) -> Result<ReadTable<SessionsExpiryTableType>, StoreError> {
        Ok(ReadTable {
            table: self.tx.open_table(SESSIONS_EXPIRY)?,
        })
    }

    pub fn user_table(&self) -> Result<ReadTable<UserTableType>, StoreError> {
        Ok(ReadTable {
            table: self.tx.open_table(USERS)?,
        })
    }

    pub fn claims_table(&self) -> Result<ReadTable<ClaimsTableType>, StoreError> {
        Ok(ReadTable {
            table: self.tx.open_table(CLAIMS)?,
        })
    }
}

pub struct WriteTx {
    tx: WriteTransaction,
    // token: TxToken<'tx>,
    // tables: TxTables<'tx>
}

// use super::TxTables;

impl WriteTx {
    // pub(super) fn token<'tx>(&'tx self) -> TxToken<'tx> {
    //     TxToken::new()
    // }

    // pub(super) fn tables<'tx>(&'tx self) -> TxTables<'tx> {
    //     TxTables { tx: &self, keys: None }
    // }

    pub fn keys_table(&self) -> Result<WriteTable<'_, KeysTableType>, StoreError> {
        Ok(WriteTable {
            table: self.tx.open_table(KEYS)?,
        })
    }

    pub fn user_table(&self) -> Result<WriteTable<'_, UserTableType>, StoreError> {
        Ok(WriteTable {
            table: self.tx.open_table(USERS)?,
        })
    }

    pub fn claims_table(&self) -> Result<WriteTable<'_, ClaimsTableType>, StoreError> {
        Ok(WriteTable {
            table: self.tx.open_table(CLAIMS)?,
        })
    }

    pub fn sessions_table(&self) -> Result<WriteTable<'_, SessionsTableType>, StoreError> {
        Ok(WriteTable {
            table: self.tx.open_table(SESSIONS)?,
        })
    }

    pub fn sessions_expiry_table(
        &self,
    ) -> Result<WriteTable<'_, SessionsExpiryTableType>, StoreError> {
        Ok(WriteTable {
            table: self.tx.open_table(SESSIONS_EXPIRY)?,
        })
    }

    pub fn commit(self) -> Result<(), StoreError> {
        self.tx.commit().map_err(|e| match e {
            redb::CommitError::Storage(e) => e.into(),
            _ => unimplemented!("Expected that CommitError only is a StorageError"),
        })
    }

    // fn open_table<'tx, 'a, K: Key + 'static, V: Value + 'static>(&'tx self, definition: TableDefinition<'a, K, V>) -> Result<TxTable<'tx, K, V>> {
    //     Ok(TxTable(self.tx.open_table(definition)?))
    // }
}

type KeysTableWrite<'tx> = WriteTable<'tx, KeysTableType>;

pub mod keys {
    use super::*;

    pub fn get_opaque_or_create<F>(
        table: &mut KeysTableWrite<'_>,
        f: F,
    ) -> Result<KeysVOwned, StoreError>
    where
        F: FnOnce() -> KeysVOwned,
    {
        get_or_create(table, "opaque_setup", f)
    }

    pub fn get_session_key_or_create<F>(
        table: &mut KeysTableWrite<'_>,
        i: usize,
        f: F,
    ) -> Result<KeysVOwned, StoreError>
    where
        F: FnOnce() -> KeysVOwned,
    {
        let key_name = format!("session_key_{}", i);

        get_or_create(table, key_name.as_str(), f)
    }

    pub fn get_ephemeral_secret_or_create<F>(
        table: &mut KeysTableWrite<'_>,
        f: F,
    ) -> Result<KeysVOwned, StoreError>
    where
        F: FnOnce() -> KeysVOwned,
    {
        get_or_create(table, "ephemeral_secret", f)
    }

    pub fn get_ephemeral_time_or_create<F>(
        table: &mut KeysTableWrite<'_>,
        f: F,
    ) -> Result<KeysVOwned, StoreError>
    where
        F: FnOnce() -> KeysVOwned,
    {
        get_or_create(table, "ephemeral_time", f)
    }

    pub fn get_ephemeral_valid_or_create<F>(
        table: &mut KeysTableWrite<'_>,
        f: F,
    ) -> Result<KeysVOwned, StoreError>
    where
        F: FnOnce() -> KeysVOwned,
    {
        get_or_create(table, "ephemeral_valid", f)
    }

    pub fn get_or_create<F>(
        table: &mut KeysTableWrite<'_>,
        key: &str,
        f: F,
    ) -> Result<KeysVOwned, StoreError>
    where
        F: FnOnce() -> KeysVOwned,
    {
        let table = &mut table.table;
        let bytes = if let Some(bytes) = table.get(key)? {
            bytes.value().to_vec()
        } else {
            f()
        };

        Ok(bytes)
    }

    pub fn overwrite_or_get(
        table: &mut KeysTableWrite<'_>,
        key: &str,
        value: Option<KeysVOwned>,
    ) -> Result<Option<KeysVOwned>, StoreError> {
        let table = &mut table.table;
        if let Some(value) = value {
            table.insert(key, value.as_slice())?;

            Ok(Some(value))
        } else {
            Ok(table.get(key)?.map(|v| v.value().to_vec()))
        }
    }

    pub fn overwrite_public_key_or_get(
        table: &mut KeysTableWrite<'_>,
        value: Option<KeysVOwned>,
    ) -> Result<Option<KeysVOwned>, StoreError> {
        overwrite_or_get(table, "public_key", value)
    }
}
type UsersK = &'static str;
type UsersV = &'static [u8];
pub const USERS: TableDefinition<UsersK, UsersV> = TableDefinition::new("users");
// // type UserTable = Table<UsersK, UsersV>;
// struct UserTable<'tx>(Table<'tx, UsersK, UsersV>);

// impl<'tx> UserTable<'tx> {
//     pub fn insert(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
//         self.0.insert(key, value)?;

//         Ok(())
//     }
// }

pub trait ReadableTable<K: Key + 'static, V: Value + 'static> {
    fn get<'tbl, 'k>(
        &'tbl self,
        key: impl Borrow<<K as Value>::SelfType<'k>>,
    ) -> Result<Option<ReadGuard<'tbl, V>>, StoreError>;

    fn range<'tbl, 'k, KB: Borrow<<K as Value>::SelfType<'k>> + 'k>(
        &'tbl self,
        range: impl RangeBounds<KB> + 'k,
    ) -> Result<Vec<(ReadGuard<'tbl, K>, ReadGuard<'tbl, V>)>, StoreError>;

    fn iter(&self) -> Result<Vec<(ReadGuard<'_, K>, ReadGuard<'_, V>)>, StoreError>;
}

// impl<'tx> ReadableTable<UsersK, UsersV> for UserTable<'tx> {
//     fn get<'tbl, 'k>(&'tbl self, key: impl Borrow<<UsersK as Value>::SelfType<'k>>) -> Result<Option<ReadGuard<'tbl, UsersV>>, StoreError> {
//         Ok(self.0.get(key)?.map(|g| ReadGuard(g)))
//     }
// }

type ClaimsK = &'static str;
type ClaimsV = &'static [u8];
pub const CLAIMS: TableDefinition<ClaimsK, ClaimsV> = TableDefinition::new("claims");

pub trait TableType {
    type Key: Key + 'static;
    type Value: Value + 'static;
}

pub struct UserTableType;

impl TableType for UserTableType {
    type Key = UsersK;
    type Value = UsersV;
}

pub struct ClaimsTableType;

impl TableType for ClaimsTableType {
    type Key = ClaimsK;
    type Value = ClaimsV;
}

pub struct WriteTable<'tx, T: TableType> {
    table: Table<'tx, T::Key, T::Value>,
}

impl<'tx, T: TableType> WriteTable<'tx, T> {
    pub fn insert<'kv>(
        &mut self,
        key: impl Borrow<<T::Key as Value>::SelfType<'kv>>,
        value: impl Borrow<<T::Value as Value>::SelfType<'kv>>,
    ) -> Result<(), StoreError> {
        self.table.insert(key, value)?;

        Ok(())
    }
}

pub struct ReadTable<T: TableType> {
    table: ReadOnlyTable<T::Key, T::Value>,
}

// Some of the typing here is buggy an dmaybe rust-analyzer is crashing? TODO investigate
impl<'tx, T: TableType> ReadableTable<T::Key, T::Value> for WriteTable<'tx, T> {
    fn get<'tbl, 'k>(
        &'tbl self,
        key: impl Borrow<<T::Key as Value>::SelfType<'k>>,
    ) -> Result<Option<ReadGuard<'tbl, T::Value>>, StoreError> {
        Ok(self.table.get(key)?.map(ReadGuard))
    }

    fn range<'tbl, 'k, KB: Borrow<<T::Key as Value>::SelfType<'k>> + 'k>(
        &'tbl self,
        range: impl RangeBounds<KB> + 'k,
    ) -> Result<Vec<(ReadGuard<'tbl, T::Key>, ReadGuard<'tbl, T::Value>)>, StoreError> {
        let range_result: Result<Vec<_>, _> = self
            .table
            .range(range)?
            .map(|kv| kv.map(|(k, v)| (ReadGuard(k), ReadGuard(v))))
            .collect();

        Ok(range_result?)
    }

    fn iter(&self) -> Result<Vec<(ReadGuard<'_, T::Key>, ReadGuard<'_, T::Value>)>, StoreError> {
        let result: Result<Vec<_>, _> = self
            .table
            .iter()?
            .map(|kv| kv.map(|(k, v)| (ReadGuard(k), ReadGuard(v))))
            .collect();

        Ok(result?)
    }
}

impl<'tx, T: TableType> ReadableTable<T::Key, T::Value> for ReadTable<T> {
    fn get<'tbl, 'k>(
        &'tbl self,
        key: impl Borrow<<T::Key as Value>::SelfType<'k>>,
    ) -> Result<Option<ReadGuard<'tbl, T::Value>>, StoreError> {
        Ok(self.table.get(key)?.map(ReadGuard))
    }

    fn range<'tbl, 'k, KB: Borrow<<T::Key as Value>::SelfType<'k>> + 'k>(
        &'tbl self,
        range: impl RangeBounds<KB> + 'k,
    ) -> Result<Vec<(ReadGuard<'tbl, T::Key>, ReadGuard<'tbl, T::Value>)>, StoreError> {
        let range_result: Result<Vec<_>, _> = self
            .table
            .range(range)?
            .map(|kv| kv.map(|(k, v)| (ReadGuard(k), ReadGuard(v))))
            .collect();

        Ok(range_result?)
    }

    fn iter(&self) -> Result<Vec<(ReadGuard<'_, T::Key>, ReadGuard<'_, T::Value>)>, StoreError> {
        let result: Result<Vec<_>, _> = self
            .table
            .iter()?
            .map(|kv| kv.map(|(k, v)| (ReadGuard(k), ReadGuard(v))))
            .collect();

        Ok(result?)
    }
}

//type ReadClaimsTable = ReadOnlyTable<ClaimsK, ClaimsV>;

// pub struct EphemeralEntry {
//     pub user_id: String,
//     pub expires: u64,
//     entropy: String,
//     pub eph_type: EphemeralType,
//     pub value: Option<String>,
// }

// impl EphemeralEntry {
//     // If expires_in is set to None, it will default to 30 minutes
//     pub fn new(
//         user_id: &str,
//         eph_type: EphemeralType,
//         entropy: String,
//         expires_in: Option<u64>,
//         value: String,
//     ) -> Self {
//         let now = SystemTime::now()
//             .duration_since(SystemTime::UNIX_EPOCH)
//             .unwrap()
//             .as_secs();
//         let expires = expires_in.unwrap_or(1800) + now;

//         Self {
//             user_id: user_id.into(),
//             entropy,
//             eph_type,
//             expires,
//             value: Some(value),
//         }
//     }

//     fn without_value(key: &str) -> Self {
//         let split: Vec<&str> = key.split(':').collect();

//         if split.len() < 4 {
//             panic!("Entry does not have correct format!")
//         }

//         let user_id = split[0..(split.len() - 3)].join(":");
//         let eph_type = split[split.len() - 3].to_owned();
//         let entropy = split[split.len() - 2].to_owned();

//         // 384 bits nonce, i.e. 48 bytes, 64 base64url characters, which are all 1 byte, so 64 bytes
//         assert_eq!(entropy.len(), 64);

//         let expires: u64 = split[split.len() - 1].parse().unwrap();

//         Self {
//             user_id,
//             expires,
//             entropy,
//             eph_type: EphemeralType::from_key_name(&eph_type).unwrap(),
//             value: None,
//         }
//     }

//     fn with_value(self, value: &str) -> Self {
//         Self {
//             user_id: self.user_id,
//             expires: self.expires,
//             entropy: self.entropy,
//             eph_type: self.eph_type,
//             value: Some(value.to_owned()),
//         }
//     }

//     pub fn key(&self) -> String {
//         format!(
//             "{}:{}:{}:{}",
//             self.user_id,
//             self.eph_type.key_name(),
//             self.entropy,
//             self.expires
//         )
//     }
// }

// pub fn write_ephemeral(
//     state: &impl State,
//     application: &str,
//     entry: EphemeralEntry,
// ) -> Result<(), DbError> {
//     let tables = state.app_tables(application);

//     let write_txn = state.db().begin_write()?;
//     {
//         let mut table = write_txn.open_table(tables.ephemeral())?;
//         table.insert(entry.key().as_str(), entry.value.unwrap().as_str())?;
//     }
//     write_txn.commit()?;

//     Ok(())
// }

// /// Reads the provided key, removing it in the process. Should be used only for ephemeral, one-time keys.
// /// Do not use for keys which are supposed to represent revocations, as they will be removed, voiding the revocation.
// pub fn pop_ephemeral(
//     state: &impl State,
//     application: &str,
//     key: &str,
//     allowed_types: Vec<EphemeralType>,
// ) -> Result<Option<EphemeralEntry>, DbError> {
//     let empty_entry = EphemeralEntry::without_value(key);

//     if allowed_types.iter().all(|t| *t != empty_entry.eph_type) {
//         panic!("Types do no match for state!")
//     }
//     let tables = state.app_tables(application);
//     let write_txn = state.db().begin_write()?;
//     let eph_data = {
//         let mut table = write_txn.open_table(tables.ephemeral())?;
//         let access = table.remove(key)?;
//         access.map(|d| {
//             let value = d.value();

//             empty_entry.with_value(value)
//         })
//     };
//     write_txn.commit()?;

//     Ok(eph_data)
// }

// pub fn set_login(state: &impl State, login: &Login, application: &str) -> Result<(), DbError> {
//     let buf = login.serialize();
//     let user_id = login.user_id.as_str();
//     let tables = state.app_tables(application);
//     let write_txn = state.db().begin_write()?;
//     {
//         let mut table = write_txn.open_table(tables.users())?;
//         table.insert(user_id, buf.as_slice())?;
//     }
//     write_txn.commit()?;

//     Ok(())
// }

#[derive(Error, Debug)]
pub enum LoginFieldError {
    #[error("Could not set login: user {0} already exists.")]
    AlreadyExists(String),
    #[error("Could not set login: user {0} does not exist.")]
    NotFound(String),
    #[error("Could not set password for user {0}: already set.")]
    PasswordSet(String),
}

pub struct ReadGuard<'a, V: Value + 'static>(AccessGuard<'a, V>);

impl<'a, V: Value + 'static> ReadGuard<'a, V> {
    pub fn value(&self) -> V::SelfType<'_> {
        self.0.value()
    }
}

pub mod users {
    use crate::data::{SessionClaimsView, UserClaims, UserPassword};

    use super::*;

    pub fn get_login(store: &Store, user_id: &str) -> Result<Option<UserPassword>, StoreError> {
        let tx = store.open_read()?;

        let table = tx.user_table()?;

        let access = table.get(user_id)?;

        if let Some(access) = access {
            let login_bytes = access.value();

            Ok(Some(UserPassword::deserialize(login_bytes)))
        } else {
            Ok(None)
        }
    }

    /// Returns the found claims, as well as requested claims that could not be found.
    pub fn get_login_claims_bytes<'a>(
        store: &Store,
        user_id: &str,
        requested_claims: &'a SessionClaims,
    ) -> Result<(ByteOwned<Claims>, SessionClaimsView<'a>), StoreError> {
        let tx = store.open_read()?;

        let table = tx.claims_table()?;

        let access = table.get(user_id)?;

        if let Some(access) = access {
            let login_bytes = access.value();

            let login = UserClaims::deserialize(login_bytes);

            Ok(if let SessionClaims::Some(subset) = requested_claims {
                // This is very cheap since it's a zero-copy deserialization
                let claim_view = login.claims.deserialize();

                let (claims, not_found) = claim_view.subset_serialize(subset);
                (claims, SessionClaimsView::Some(not_found))
            } else {
                // While later we only need a reference, we clone here to not have to keep the table "open" beyond this function
                (login.claims.to_owned(), SessionClaimsView::Some(Vec::new()))
            })
        } else {
            Ok(match requested_claims {
                SessionClaims::All => (empty_claim_bytes().to_owned(), SessionClaimsView::All),
                SessionClaims::Some(not_found) => (
                    empty_claim_bytes().to_owned(),
                    SessionClaimsView::Some(not_found.iter().map(|s| s.as_str()).collect()),
                ),
            })
        }
    }

    pub fn set_login_claims(store: &Store, claims: UserClaims) -> Result<(), StoreError> {
        let tx = store.open_write()?;

        {
            let mut table = tx.claims_table()?;

            table.insert(claims.user_id.as_str(), claims.serialize().as_slice())?;
        }

        tx.commit()?;

        Ok(())
    }
}

pub mod sessions {
    use sha2::Sha512;

    use crate::{data::SessionStatus, Session};

    use super::*;

    pub fn session_status(store: &Store, session: &Session) -> Result<SessionStatus, StoreError> {
        let mut hasher = Sha512::new();
        hasher.update(session.raw_bytes());
        let result: [u8; 64] = hasher.finalize().into();

        let tx = store.open_read()?;

        let table = tx.sessions_table()?;

        let status = table.get(&result)?;

        Ok(match status.map(|s| s.value()) {
            Some((status, expires)) => SessionStatus::from_raw_status(status, expires),
            None => SessionStatus::untracked(),
        })
    }
}

// pub struct SetLoginOptions {
//     require_unset_password: bool,
//     create_user: bool,
// }

// impl SetLoginOptions {
//     pub fn new(require_unset_password: bool, create_user: bool) -> Self {
//         Self {
//             require_unset_password,
//             create_user,
//         }
//     }
// }

// // For EphemeralType = ChangePassword, old_login_bytes must be set.

// /// If `require_unset_password` is set to false, it returns a [LoginFieldError::PasswordSet] when password is already set.
// /// If `create_user` is set to true, it will create a user when the user does not exist. Otherwise, it
// /// will return a [LoginFieldError::AlreadyExists]. When set to false, it will instead return [LoginFieldError::NotFound]
// /// when the user does not exist.
// pub fn set_login_field_write(
//     write_txn: &WriteTransaction,
//     state: &impl State,
//     application: &str,
//     user_id: &str,
//     password_file: Option<String>,
//     claims: Option<impl SerializedAs<Claims>>,
//     options: SetLoginOptions,
// ) -> Result<(), OneOf<(DbError, LoginFieldError)>> {
//     // One of the two must be set
//     assert!(password_file.is_some() || claims.is_some());

//     let tables = state.app_tables(application);
//     let mut table = write_txn.open_table(tables.users()).to_one_of_two()?;

//     let user_bytes = {
//         let access = table.get(user_id).to_one_of_two()?;

//         if let Some(access) = access {
//             let user_bytes = access.value();
//             let mut user: Login = Login::deserialize(user_bytes);
//             if options.create_user {
//                 return Err(OneOf::new(LoginFieldError::AlreadyExists(
//                     user_id.to_owned(),
//                 )));
//             }
//             if options.require_unset_password && !user.password_file.is_empty() {
//                 return Err(OneOf::new(LoginFieldError::PasswordSet(user_id.to_owned())));
//             }

//             if let Some(password_file) = password_file {
//                 user.password_file = password_file;
//             }
//             if let Some(claims) = claims {
//                 user.claims = claims.serialized();
//                 user.serialize()
//             } else {
//                 user.serialize()
//             }
//         } else if options.create_user {
//             // Password file must contain value when creating user!
//             assert!(password_file.is_some());
//             if let Some(claims) = claims {
//                 let login = Login {
//                     user_id: user_id.to_owned(),
//                     password_file: password_file.unwrap(),
//                     claims: claims.serialized(),
//                 };

//                 login.serialize()
//             } else {
//                 let claims = Claims::empty().serialize();
//                 let login = Login {
//                     user_id: user_id.to_owned(),
//                     password_file: password_file.unwrap(),
//                     claims: claims.as_packed(),
//                 };

//                 login.serialize()
//             }
//         } else {
//             return Err(OneOf::new(LoginFieldError::NotFound(user_id.to_owned())));
//         }
//     };

//     table
//         .insert(user_id, user_bytes.as_slice())
//         .to_one_of_two()?;

//     Ok(())
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::data::Login;
//     use crate::state::test_util::*;

//     #[test]
//     fn login_set_read() {
//         let claims_bytes = Claims::new(vec![
//             ("claim1", "is_this"),
//             ("claim2", "is_that"),
//             ("claim3", "is_thatd"),
//         ])
//         .serialize();
//         let value = Login {
//             user_id: "hi".to_owned(),
//             password_file: "pw".to_owned(),
//             claims: claims_bytes.as_packed(),
//         };

//         let app = "abc";

//         let state = TestState::setup_test(vec![app]);

//         set_login(&state, &value, app).unwrap();

//         let read_login = get_login(&state, app, &value.user_id).unwrap().unwrap();

//         assert_eq!(value.user_id, read_login.user_id);
//         assert_eq!(value.password_file, read_login.password_file);

//         let read_login = get_login_claims_bytes(&state, app, &value.user_id, SessionClaims::All)
//             .unwrap()
//             .unwrap();

//         assert_eq!(claims_bytes, read_login);
//     }
// }
