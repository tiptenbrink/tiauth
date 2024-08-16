#![allow(dead_code)]
use ambassador::delegatable_trait;
use base64::{engine::general_purpose as b64, Engine as _};
use redb::Database;
use typed_arena::Arena;
use opaque_borink::create_setup;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::borrow::Borrow;
use std::cell::{OnceCell, RefCell};
use std::panic::Location;
use std::sync::{atomic, LazyLock, OnceLock, RwLock, Weak};
// use redb::{Database, Error as DbError, ReadableTable, TableDefinition};
use rmp_serde::{decode, encode};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::Arc;
#[cfg(any(not(target_arch = "wasm32"), not(target_os = "unknown")))]
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use web_time::SystemTime;

use crate::counter::{CompactSet, Counter};
use crate::crypto::{
    create_key, create_symmetric_key, load_key, load_public_key, save_private_key, save_public_key,
    Key, PublicKey,
};
use crate::data::{Application, SessionKey, EPHEMERAL_INTERVAL};
use crate::proof::EphemeralKey;
use crate::store::{
    keys, DataDeserializationErrorSource, Store, StoreAddress, StoreError, StoreType,
    WrapDeserializationError, WrapVecTryFromError,
};

// pub trait GovernorState: State {
//     type Readonly;

//     fn add_app_to_state(&mut self, application: &Application);

//     fn register_application(&mut self, application: &Application) -> Result<(), DbError> {
//         write_app_to_db(self.db(), application)?;

//         self.add_app_to_state(application);
//         self.keys_mut()
//             .register_application(&application.name, None);

//         Ok(())
//     }

//     fn remove_app_from_state(&mut self, application: &str);

//     fn deregister_application(&mut self, application: &str) -> Result<(), DbError> {
//         let tables = self.app_tables(application);

//         remove_app_from_db(self.db(), application, tables)?;

//         self.remove_app_from_state(application);

//         Ok(())
//     }

//     // fn app_tables(&self, application: &str) -> AppTable;

//     // fn app_key(&self, application: &str) -> PublicKey;

//     // fn apps(&self) -> Vec<&String>;

//     // fn db(&self) -> &Database;

//     // fn keys(&self) -> &impl GovernorKeyState<2>;

//     fn keys_mut(&mut self) -> &mut impl GovernorKeyState<2>;

//     fn rng(&self) -> StdRng {
//         StdRng::from_entropy()
//     }

//     // fn private(&self) -> &PrivateState;

//     fn from_init(init_state: InitState<2>) -> Self;

//     fn setup<P: AsRef<Path>>(db_path: P, now: u64) -> Result<Self, DbError>
//     where
//         Self: Sized,
//     {
//         let mut state = Self::from_init(InitState::init(db_path, now)?);

//         let registered_apps = get_apps(state.db())?;

//         for app in registered_apps {
//             state.add_app_to_state(&app);
//         }

//         Ok(state)
//     }
// }

pub trait GovernorState: State {

    // fn app_tables(&self, application: &str) -> AppTable;

    // fn app_key(&self, application: &str) -> PublicKey;

    // fn apps(&self) -> Vec<&String>;

    // fn db(&self) -> &Database;

    // fn keys(&self) -> &impl GovernorKeyState<2>;

    fn keys_mut(&mut self) -> &mut impl GovernorKeyState<2>;

    // fn private(&self) -> &PrivateState;

    // fn from_init(init_state: InitState<2>) -> Self;

    // fn setup<P: AsRef<Path>>(db_path: P, now: u64) -> Result<Self, DbError>
    // where
    //     Self: Sized,
    // {
    //     let mut state = Self::from_init(InitState::init(db_path, now)?);

    //     let registered_apps = get_apps(state.db())?;

    //     for app in registered_apps {
    //         state.add_app_to_state(&app);
    //     }

    //     Ok(state)
    // }
}

pub trait State: DriverState + AppState + CounterState + Send + Sync + 'static {}

#[delegatable_trait]
pub trait DriverState {
    // Seconds since the epoch
    fn time(&self) -> u64;

    fn drive_time(&self, time: u64);
}

#[delegatable_trait]
pub trait CounterState {
    fn counter_next(&self, key: &str, expires: u64) -> u64;

    fn counter_used(&self, key: &str, num: u64, expires: u64, time: u64) -> bool;
}

#[delegatable_trait]
pub trait AppState {
    fn application(&self) -> &str;

    fn public_key(&self) -> &PublicKey;

    fn store(&self) -> &Store;

    // fn private(&self) -> &PrivateState;

    fn keys(&self) -> &impl KeyState<2>;
}

// impl<T: GovernorState> State for T {
//     fn app_tables(&self, application: &str) -> AppTable {
//         self.app_tables(application)
//     }

//     fn app_key(&self, application: &str) -> PublicKey {
//         self.app_key(application)
//     }

//     fn db(&self) -> &Database {
//         self.db()
//     }

//     fn private(&self) -> &PrivateState {
//         self.private()
//     }

//     fn apps(&self) -> Vec<&String> {
//         self.apps()
//     }

//     fn keys(&self) -> &impl KeyState<2> {
//         self.keys()
//     }
// }

// impl<const SN: usize, T: GovernorKeyState<SN>> KeyState<SN> for T {
//     fn opaque(&self) -> &str {
//         self.opaque()
//     }

//     fn sess_veri_keys(&self) -> &[SessionKey; SN] {
//         self.sess_veri_keys()
//     }

//     fn eph_veri_keys(&self, application: &str) -> (Vec<EphemeralKey>, usize) {
//         self.eph_veri_keys(application)
//     }

//     fn ephemeral_key(&self, application: &str) -> EphemeralKey {
//         self.ephemeral_key(application)
//     }
// }

pub trait GovernorKeyState<const SN: usize>: KeyState<SN> {
    fn rotate_session_keys(&mut self, key: SessionKey);

    // Moves all keys from the invalidated key to the end one place left, and puts the new key at the end. If the key does not exist, it must call rotate_session_keys.
    fn invalidate_session_key(&mut self, key_to_invalidate: &SessionKey, new_key: SessionKey);

    fn update_ephemeral_time(&mut self, time: u64);

    fn rotate_opaque(&mut self) {
        todo!()
    }
}

pub trait KeyState<const SN: usize> {
    fn opaque(&self) -> &str;

    fn sess_veri_keys(&self) -> &[SessionKey; SN];

    fn session_key(&self) -> &SessionKey {
        self.sess_veri_keys().last().unwrap()
    }

    fn eph_veri_keys(&self, time: u64) -> Vec<EphemeralKey>;

    fn ephemeral_key(&self, time: u64) -> EphemeralKey;
}

#[derive(Clone)]
struct AppSecret {
    base_seed: [u8; 32],
    amount_valid: usize,
}

#[derive(Clone)]
pub struct KeyStateImpl<const SN: usize> {
    valid_session_keys: [SessionKey; SN],
    ephemeral_time: u64,
    ephemeral_secret: [u8; 32],
    ephemeral_valid: u32,
    opaque: String,
}

impl<const SN: usize> KeyState<SN> for KeyStateImpl<SN> {
    fn opaque(&self) -> &str {
        &self.opaque
    }

    fn eph_veri_keys(&self, now: u64) -> Vec<EphemeralKey> {
        EphemeralKey::last::<EPHEMERAL_INTERVAL>(
            self.ephemeral_secret,
            now,
            self.ephemeral_time,
            self.ephemeral_valid,
        )
    }

    fn sess_veri_keys(&self) -> &[SessionKey; SN] {
        &self.valid_session_keys
    }

    fn ephemeral_key(&self, now: u64) -> EphemeralKey {
        EphemeralKey::compute::<EPHEMERAL_INTERVAL>(self.ephemeral_secret, now, self.ephemeral_time)
    }
}

// fn create_app_secret(
//     base_secret: &[u8; 32],
//     application: &str,
//     amount_valid: Option<usize>,
// ) -> AppSecret {
//     let mut hasher = Sha256::new();

//     hasher.update(application.as_bytes());
//     hasher.update(*base_secret);

//     let base_seed: [u8; 32] = hasher.finalize().into();

//     let amount_valid = amount_valid.unwrap_or(2);

//     AppSecret {
//         amount_valid,
//         base_seed,
//     }
// }

impl<const SN: usize> GovernorKeyState<SN> for KeyStateImpl<SN> {
    fn rotate_session_keys(&mut self, key: SessionKey) {
        self.valid_session_keys.rotate_left(1);
        self.valid_session_keys[SN - 1] = key;
    }

    fn invalidate_session_key(&mut self, key_to_invalidate: &SessionKey, new_key: SessionKey) {
        let invalid_key_i = self
            .valid_session_keys
            .iter()
            .position(|s| s == key_to_invalidate);

        if let Some(invalid_key_i) = invalid_key_i {
            for i in invalid_key_i..(SN - 1) {
                self.valid_session_keys[i] = self.valid_session_keys[i + 1].clone()
            }
            self.valid_session_keys[SN - 1] = new_key;
        } else {
            self.rotate_session_keys(new_key)
        }
    }

    fn update_ephemeral_time(&mut self, now: u64) {
        self.ephemeral_time = now;
    }
}

// #[derive(Clone)]
// pub struct ServerStateImpl {
//     // Persistent database for overall configuration and app information
//     pub store: Arc<Store>,
//     pub base_address: StoreAddress,
//     pub app_stores: Arc<HashMap<String, OnceLock<Store>>>,
// }

pub struct ServerThreadState {
    // Persistent database for overall configuration and app information
    pub state: AppStateImpl,
}

// thread_local! {
//     pub static STATE: RefCell<OnceCell<ServerThreadState>> = RefCell::new(OnceCell::new());
// }

// fn 

// impl ServerState for ServerStateImpl {
//     fn app(&self, application: String) -> &impl State {
//         self.apps.get(&application).unwrap()
//             .get_or_init(|| {
//                 let address = self.base_address.join_name(&application);
//                 let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
//                 load_app_state(&application, address, None, now).unwrap()
//             })
//     }

//     fn apps(&self) -> Vec<&String> {
//         self.apps.keys().into_iter().collect()
//     }
// }


pub struct AppStateImpl {
    pub application: String,
    // Public key used to verify proof signatures
    pub public_key: PublicKey,
    // Counter used to ensure ephemeral validity
    pub counter: Counter,
    pub compact_set: CompactSet,
    // Persistent database
    pub store: Store,
    // Keys and secrets
    pub key_state: KeyStateImpl<2>,
    pub time: AtomicU64,
}

impl AppStateImpl {
    pub fn load_app_state(
        application: &str,
        address: StoreAddress,
        public_key: Option<PublicKey>,
        now: u64,
    ) -> Result<AppStateImpl, StoreError> {
        let store = Store::load(address, StoreType::Application)?;
    
        let AppInitState {
            opaque,
            ephemeral_secret,
            public_key,
            session_keys,
            ephemeral_valid,
            ephemeral_time,
        } = init_app_state(&store, public_key, &mut StdRng::from_entropy(), now)?;
    
        let key_state = KeyStateImpl {
            opaque,
            valid_session_keys: session_keys,
            ephemeral_secret,
            ephemeral_valid,
            ephemeral_time,
        };
    
        let counter = Counter::new();
        let compact_set = CompactSet::new();
        let time = AtomicU64::new(now);
    
        let app_state = AppStateImpl {
            application: application.to_owned(),
            public_key,
            counter,
            compact_set,
            store: store,
            key_state,
            time,
        };
    
        Ok(app_state)
    }
}

// fn register_application_tables(map: &mut HashMap<String, TableStore>, application: &str) {
//     let session_name = format!("{}:sessions", application);
//     let user_name = format!("{}:users", application);
//     let state_name = format!("{}:ephemeral", application);

//     map.insert(
//         application.to_owned(),
//         (session_name, user_name, state_name),
//     );
// }

impl AppState for AppStateImpl {
    fn store(&self) -> &Store {
        &self.store
    }

    // fn private(&self) -> &PrivateState {
    //     &self.private
    // }

    fn keys(&self) -> &impl KeyState<2> {
        &self.key_state
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn application(&self) -> &str {
        &self.application
    }
}

impl CounterState for AppStateImpl {
    fn counter_next(&self, _: &str, _expires: u64) -> u64 {
        // It should be possible to in the future make this counter be per-user, or to store the fact that the counter has been given out
        self.counter.increment()
    }

    fn counter_used(&self, _: &str, num: u64, expires: u64, time: u64) -> bool {
        self.compact_set.num_exists(num, expires, Some(time))
    }
}

impl DriverState for AppStateImpl {
    fn time(&self) -> u64 {
        self.time.load(atomic::Ordering::Relaxed)
    }

    fn drive_time(&self, time: u64) {
        self.time.store(time, atomic::Ordering::Relaxed)
    }
}

impl State for AppStateImpl {}

impl GovernorState for AppStateImpl {

    fn keys_mut(&mut self) -> &mut impl GovernorKeyState<2> {
        &mut self.key_state
    }
}

// pub struct InitState<const SN: usize> {
//     pub db: Database,
//     pub key_init: KeyInitState<SN>,
//     pub opaque
// }

// impl<const SN: usize> InitState<SN> {
//     fn init<P: AsRef<Path>>(db_path: P, now: u64) -> Result<Self, DbError> {
//         let db = open_db(db_path)?;
//         let mut rng = StdRng::from_entropy();
//         let private = init_private_state(&db, &mut rng)?;
//         let key_init = init_key_state(&db, &mut rng, now)?;

//         Ok(Self {
//             db,
//             private,
//             key_init,
//         })
//     }
// }

pub struct AppInitState<const SN: usize> {
    pub opaque: String,
    pub ephemeral_secret: [u8; 32],
    pub public_key: PublicKey,
    pub session_keys: [SessionKey; SN],
    pub ephemeral_valid: u32,
    pub ephemeral_time: u64,
}

fn init_app_state<const SN: usize>(
    store: &Store,
    public_key: Option<PublicKey>,
    rng: &mut StdRng,
    now: u64,
) -> Result<AppInitState<SN>, StoreError> {
    let tx = store.open_write()?;

    let (opaque, session_keys, public_key, ephemeral_secret, ephemeral_valid, ephemeral_time) = {
        let mut table = tx.keys_table()?;

        let setup = keys::get_opaque_or_create(&mut table, || create_setup().into_bytes())?;
        let setup = String::from_utf8(setup).to_deser_err("opaque setup")?;

        let session_keys: Result<Vec<SessionKey>, StoreError> = (0..SN)
            .map(|i| {
                let session_key_bytes = keys::get_session_key_or_create(&mut table, i, || {
                    let session_key = SessionKey::create(rng);
                    session_key.to_saved_bytes().to_vec()
                })?;

                Ok(SessionKey::from_saved_bytes(&session_key_bytes)
                    .to_deser_err(format!("session key {}", i))?)
            })
            .collect();

        let session_keys: [SessionKey; SN] = session_keys?.try_into().unwrap();

        let ephemeral_secret = keys::get_ephemeral_secret_or_create(&mut table, || {
            let mut ephemeral_secret = vec![0u8; 32];
            rng.fill_bytes(&mut ephemeral_secret);

            ephemeral_secret
        })?;
        let ephemeral_secret = TryInto::<[u8; 32]>::try_into(ephemeral_secret)
            .to_deser_err(32, "ephemeral secret length")?;

        let ephemeral_time =
            keys::get_ephemeral_time_or_create(&mut table, || now.to_string().into_bytes())?;
        let time_str = String::from_utf8(ephemeral_time).to_deser_err("ephemeral time to str")?;
        let ephemeral_time = time_str
            .parse::<u64>()
            .to_deser_err("ephemeral time str as u64")?;

        let ephemeral_valid =
            keys::get_ephemeral_valid_or_create(&mut table, || 2.to_string().into_bytes())?;
        let valid_str =
            String::from_utf8(ephemeral_valid).to_deser_err("ephemeral valid to str")?;
        let ephemeral_valid = valid_str
            .parse::<u32>()
            .to_deser_err("ephemeral valid str as u32")?;

        let public_key_bytes = public_key.map(|k| save_public_key(&k).pem().into_bytes());
        let public_key_bytes = keys::overwrite_public_key_or_get(&mut table, public_key_bytes)?
            .ok_or_else(|| {
                StoreError::new_init("No public key set for application and none provided!")
            })?;
        let public_key_pem = String::from_utf8(public_key_bytes).to_deser_err("public key pem")?;
        let public_key = load_public_key(&public_key_pem).to_deser_err("public key")?;

        (
            setup,
            session_keys,
            public_key,
            ephemeral_secret,
            ephemeral_valid,
            ephemeral_time,
        )
    };
    tx.commit()?;

    Ok(AppInitState {
        opaque,
        session_keys,
        public_key,
        ephemeral_secret,
        ephemeral_valid,
        ephemeral_time,
    })
}

// fn init_private_state(db: &Database, rng: &mut StdRng) -> Result<PrivateState, DbError> {
//     let write_txn = db.begin_write()?;

//     let (opaque, session, private) = {
//         let mut table = write_txn.open_table(SERVER)?;
//         let setup = table.get("opaque_setup")?.map(|a| a.value());

//         let setup = if let Some(setup) = setup {
//             setup
//         } else {
//             let setup = create_setup();
//             table.insert("opaque_setup", setup.clone())?;
//             setup
//         };

//         let session_key = table.get("session_key")?.map(|a| a.value());

//         let session_key = if let Some(session_key) = session_key {
//             load_session_key(&session_key)
//         } else {
//             let session_key = create_session_key(rng);
//             let saved_session_key = save_session_key(&session_key);

//             table.insert("session_key", saved_session_key.session)?;
//             session_key
//         };

//         let private_key = table.get("private_key")?.map(|a| a.value());

//         let keypair = if let Some(private_key) = private_key {
//             load_key(&private_key).unwrap()
//         } else {
//             let keypair = create_key();
//             let saved_private_key = save_private_key(&keypair);

//             table.insert("private_key", saved_private_key)?;
//             keypair
//         };

//         (setup, session_key, keypair)
//     };
//     write_txn.commit()?;

//     Ok(PrivateState {
//         opaque,
//         session,
//         private,
//     })
// }

// pub fn write_app_to_db(db: &Database, application: &Application) -> Result<(), DbError> {
//     let app_buf = encode::to_vec_named(&application).unwrap();

//     let write_txn = db.begin_write()?;
//     {
//         let mut table = write_txn.open_table(APPS)?;
//         table
//             .insert(application.name.as_str(), app_buf.as_slice())
//             .unwrap();
//     }
//     write_txn.commit()?;

//     Ok(())
// }

// pub fn remove_app_from_db(
//     db: &Database,
//     application: &str,
//     tables: AppTable,
// ) -> Result<(), DbError> {
//     let write_txn = db.begin_write()?;
//     {
//         let mut table = write_txn.open_table(APPS)?;
//         table.remove(application)?;

//         for t in tables.all() {
//             // This is a fake definition with wrong types, but the types don't have to match to delete the table
//             let definition: TableDefinition<String, String> = TableDefinition::new(&t);
//             write_txn.delete_table(definition)?;
//         }
//     }
//     write_txn.commit()?;

//     Ok(())
// }

// fn get_apps(db: &Database) -> Result<Vec<Application>, DbError> {
//     let write_txn = db.begin_write()?;
//     let apps = {
//         let table = write_txn.open_table(APPS)?;

//         let mut apps = Vec::new();

//         for app_entry in table.iter()? {
//             let (_, app_bytes) = app_entry?;

//             let app_bytes = app_bytes.value();

//             let app: Application = decode::from_read(app_bytes).unwrap();

//             apps.push(app);
//         }

//         apps
//     };

//     write_txn.commit()?;

//     Ok(apps)
// }

#[cfg(feature = "test")]
pub mod test_util {
    use std::{cell::RefCell, ops::Deref};

    use camino::Utf8Path;

    use super::*;
    use crate::crypto::{save_public_key, Key};

    fn create_app(application: &str) -> (Key, Application) {
        let key = create_key();

        let public_key = save_public_key(&key.to_public_key());

        let app = Application::new(public_key, application);

        (key, app)
    }

    /// TestState also contains application private keys for easier testing.
    pub struct TestState {
        pub state: AppStateImpl,
        pub time: AtomicU64,
        key: Key,
    }

    impl AppState for TestState {
        fn application(&self) -> &str {
            self.state.application()
        }

        fn public_key(&self) -> &PublicKey {
            self.state.public_key()
        }

        fn store(&self) -> &Store {
            self.state.store()
        }

        fn keys(&self) -> &impl KeyState<2> {
            self.state.keys()
        }
    }

    impl CounterState for TestState {
        fn counter_next(&self, key: &str, expires: u64) -> u64 {
            self.state.counter_next(key, expires)
        }

        fn counter_used(&self, key: &str, num: u64, expires: u64, time: u64) -> bool {
            self.state.counter_used(key, num, expires, time)
        }
    }

    impl DriverState for TestState {
        fn time(&self) -> u64 {
            self.time.load(atomic::Ordering::Relaxed)
        }

        fn drive_time(&self, time: u64) {
            self.time.store(time, atomic::Ordering::Relaxed);
        }
    }

    impl State for TestState {}

    impl TestState {
        pub fn private_key(&self) -> &Key {
            &self.key
        }

        pub fn setup_test(app_name: &str) -> Self {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            let tmp_path = Utf8Path::from_path(tmp.path()).unwrap();

            let (key, _) = create_app(app_name);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - (86400 * 15);

            let state = AppStateImpl::load_app_state(
                app_name,
                StoreAddress::from_path(tmp_path),
                Some(key.to_public_key()),
                now,
            )
            .unwrap();

            Self {
                state,
                key,
                time: AtomicU64::new(now),
            }
        }
    }

    // impl GovernorKeyState<2> for TestKeyState {
    //     fn opaque(&self) -> &str {
    //         todo!()
    //     }

    //     fn sess_veri_keys(&self) -> &[SessionKey; 2] {
    //         todo!()
    //     }

    //     fn register_application(&mut self, application: &str, amount_valid: Option<usize>) {
    //         todo!()
    //     }

    //     fn rotate_session_keys(&mut self, key: SessionKey) {
    //         todo!()
    //     }

    //     fn invalidate_session_key(&mut self, key_to_invalidate: &SessionKey, new_key: SessionKey) {
    //         todo!()
    //     }

    //     fn update_ephemeral_time(&mut self) {
    //         todo!()
    //     }

    //     fn eph_veri_keys(&self, application: &str) -> (Vec<EphemeralKey>, usize) {
    //         todo!()
    //     }

    //     fn from_init(key_init: KeyInitState<2>) -> Self {
    //         todo!()
    //     }

    //     fn ephemeral_key(&self, application: &str) -> EphemeralKey {
    //         todo!()
    //     }
    // }

    // impl TestState {
    //     pub fn setup_test(applications: Vec<&str>) -> Self {
    //         let tmp = tempfile::NamedTempFile::new().unwrap();
    //         let now = SystemTime::now()
    //             .duration_since(UNIX_EPOCH)
    //             .unwrap()
    //             .as_secs()
    //             - (86400 * 15);

    //         let InitState {
    //             db,
    //             private,
    //             key_init,
    //         } = InitState::init(tmp.path(), now).unwrap();

    //         let mut tables: HashMap<String, TableStore> = HashMap::new();
    //         let mut app_keys: HashMap<String, Key> = HashMap::new();
    //         let mut app_public_keys: HashMap<String, PublicKey> = HashMap::new();

    //         let mut app_secrets: HashMap<String, AppSecret> = HashMap::new();

    //         for app_name in applications {
    //             let (key, _) = create_app(app_name);

    //             // TODO? check if re-enable
    //             //write_app_to_db(&db, &app).unwrap();

    //             // TODO app secrets
    //             register_application_tables(&mut tables, app_name);
    //             app_public_keys.insert(app_name.to_owned(), key.to_public_key());
    //             app_keys.insert(app_name.to_owned(), key);

    //             let app_secret = create_app_secret(&key_init.ephemeral_secret, app_name, Some(2));

    //             app_secrets.insert(app_name.to_owned(), app_secret);
    //         }

    //         let key_state = CoreKeyState {
    //             valid_session_keys: key_init.session_keys,
    //             ephemeral_secret: key_init.ephemeral_secret,
    //             ephemeral_time: key_init.ephemeral_time,
    //             app_secrets,
    //             opaque: key_init.opaque,
    //         };

    //         Self {
    //             db,
    //             private,
    //             tables,
    //             app_keys,
    //             app_public_keys,
    //             key_state,
    //         }
    //     }

    //     pub fn proof_key(&self, application: &str) -> &Key {
    //         self.app_keys.get(application).unwrap()
    //     }
    // }

    // impl State for TestState {
    //     fn app_tables(&self, application: &str) -> AppTable {
    //         let store = self.tables.get(application).unwrap();
    //         AppTable::new(store)
    //     }

    //     fn db(&self) -> &Database {
    //         &self.db
    //     }

    //     fn private(&self) -> &PrivateState {
    //         &self.private
    //     }

    //     fn app_key(&self, application: &str) -> PublicKey {
    //         self.app_public_keys.get(application).unwrap().clone()
    //     }

    //     fn apps(&self) -> Vec<&String> {
    //         self.tables.keys().collect()
    //     }

    //     fn keys(&self) -> &impl KeyState<2> {
    //         &self.key_state
    //     }
    // }

    // impl GovernorState for TestState {
    //     type Readonly = TestState;

    //     fn add_app_to_state(&mut self, _: &Application) {
    //         unimplemented!("Do not use this function for TestState. Register through `setup_test`.")
    //     }

    //     fn from_init(_: InitState<2>) -> Self {
    //         unimplemented!("Do not use this function for TestState! Use `setup_test`.")
    //     }

    //     fn setup<P: AsRef<Path>>(_: P, _: u64) -> Result<Self, DbError>
    //     where
    //         Self: Sized,
    //     {
    //         unimplemented!("Do not use this function for TestState!")
    //     }

    //     fn remove_app_from_state(&mut self, _: &str) {
    //         unimplemented!("Do not use this function for TestState!")
    //     }

    //     fn keys_mut(&mut self) -> &mut impl GovernorKeyState<2> {
    //         &mut self.key_state
    //     }
    // }
}


pub struct OnceList<K, V, F: Fn() -> V> {
    head: OnceListElement<K, V>,
    f: F
}


impl<K, V, F: Fn() -> V> OnceList<K, V, F> {
    pub const fn new(f: F) -> Self {
        OnceList { head: OnceListElement::new(), f }
    }

    pub fn insert(&self, key: K)
    where
        K: Eq,
    {
        // We don't care if it already exists, since they are all created with the same function
        self.head.insert(key, (self.f)()).ok();
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.head.get(key)
    }
}

struct OnceListElement<K, V> {
    data: OnceLock<(K, V)>,
    next: OnceLock<Box<OnceListElement<K, V>>>,
}

impl<K, V> OnceListElement<K, V> {
    const fn new() -> OnceListElement<K, V> {
        OnceListElement { data: OnceLock::new(), next: OnceLock::new() }
    }

    fn insert(&self, key: K, value: V) -> Result<(), V>
    where
        K: Eq,
    {
        if let Err((key, value)) = self.data.set((key, value)) {
            return if self.data.get().unwrap().0 != key {
                let next = self.next.get_or_init(|| Box::new(OnceListElement::new()));
                next.insert(key, value)
            } else {
                Err(value)
            }
        };

        Ok(())
    }
    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized
    {
        let mut element = self;
        loop {
            let next = if let Some((element_key, value)) = element.data.get() {
                if key == element_key.borrow() {
                    return Some(value)
                }

                element.next.get()
            } else {
                return None
            };

            if let Some(next) = next {
                element = next.as_ref()
            } else {
                return None
            }
        }
        
    }
}

pub struct OnceVec<T> {
    index: usize,
    data: OnceLock<T>,
    next: OnceLock<Box<OnceVec<T>>>,
}

impl<T> OnceVec<T> {
    pub const fn new() -> OnceVec<T> {
        OnceVec { index: 0, data: OnceLock::new(), next: OnceLock::new() }
    }
    fn with_index(index: usize) -> OnceVec<T> {
        OnceVec { index, data: OnceLock::new(), next: OnceLock::new() }
    }
    pub fn push(&self, value: T) -> usize {
        if let Err(value) = self.data.set(value) {
            let next = self.next.get_or_init(|| Box::new(OnceVec::with_index(self.index+1)));
            next.push(value)
        } else {
            self.index
        }
    }
    pub fn get(&self, index: usize) -> Option<&T>
    {
        if self.index == index {
            self.data.get()
        } else {
            self.next.get().and_then(|next| next.get(index))
        }
    }
}

struct SimpleState {
    name: String,
    db: Store
}

struct States {
    indexes: Arc<OnceList<String, AtomicU64, fn() -> AtomicU64>>,
    stores: Arc<OnceVec<SimpleState>>
}

impl States {
    fn get_state(&self, app: &str) -> &SimpleState {
        let a = self.indexes.get(app).unwrap();
        let index = a.load(atomic::Ordering::Relaxed);
        self.stores.get(index as usize).unwrap()
    }

    fn new_state<F: Fn(SimpleState) -> SimpleState>(&self, app: &str, f: F) -> &SimpleState {
        let a = self.indexes.get(app).unwrap();
        let index = a.load(atomic::Ordering::Relaxed);
        self.stores.get(index as usize).unwrap()
    }
}

struct Dbs {
    dbs: Vec<Store>
}

// fn ab(db: Arc<Database>) {
//     Location
// }


struct GState {
    data: Arena<SimpleState>
}

struct GStateView<'a> {
    data: Vec<&'a SimpleState>
}

impl<'a> GStateView<'a> {
    fn get_app_state(&self, name: &str) -> &SimpleState {
        for s in &self.data {
            if s.name == name {
                return s
            }
        }
        panic!("name should exist!")
    }
}

struct SimpleStateX {
    a: Weak<SimpleAppState>
}

struct SimpleAppState {
    
}

impl SimpleStateX {
    fn get_app_state(self) -> Arc<SimpleAppState> {
        self.a.upgrade().unwrap()
    }
}

// struct RefHolder {
//     s: Arc<SimpleState>
//     b: RwLock<>
// }

// fn make_from_r(s: SimpleState) {
//     let a = Arc::new(s);
//     Arc::new_cyclic
//     ()
// }

struct AState {
    
}

impl AState {

}