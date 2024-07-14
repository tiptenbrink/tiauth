#![allow(dead_code)]

use base64::{engine::general_purpose as b64, Engine as _};
use opaque_borink::create_setup;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use redb::{Database, Error as DbError, ReadableTable, TableDefinition};
use rmp_serde::{decode, encode};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
#[cfg(any(not(target_arch = "wasm32"), not(target_os = "unknown")))]
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use web_time::SystemTime;

use crate::crypto::{
    create_key, create_session_key, load_key, load_session_key, save_private_key, save_session_key,
    EphemeralKey, Key, PublicKey, SessionKey,
};
use crate::data::Application;
use crate::store::{open_db, AppTable, TableStore, APPS, SERVER};

pub trait GovernorState {
    type Readonly;

    fn add_app_to_state(&mut self, application: &Application);

    fn register_application(&mut self, application: &Application) -> Result<(), DbError> {
        write_app_to_db(self.db(), application)?;

        self.add_app_to_state(application);
        self.keys_mut()
            .register_application(&application.name, None);

        Ok(())
    }

    fn remove_app_from_state(&mut self, application: &str);

    fn deregister_application(&mut self, application: &str) -> Result<(), DbError> {
        let tables = self.app_tables(application);

        remove_app_from_db(self.db(), application, tables)?;

        self.remove_app_from_state(application);

        Ok(())
    }

    fn app_tables(&self, application: &str) -> AppTable;

    fn app_key(&self, application: &str) -> PublicKey;

    fn apps(&self) -> Vec<&String>;

    fn db(&self) -> &Database;

    fn keys(&self) -> &impl GovernorKeyState<2>;

    fn keys_mut(&mut self) -> &mut impl GovernorKeyState<2>;

    fn rng(&self) -> StdRng {
        StdRng::from_entropy()
    }

    fn private(&self) -> &PrivateState;

    fn from_init(init_state: InitState<2>) -> Self;

    fn setup<P: AsRef<Path>>(db_path: P, now: u64) -> Result<Self, DbError>
    where
        Self: Sized,
    {
        let mut state = Self::from_init(InitState::init(db_path, now)?);

        let registered_apps = get_apps(state.db())?;

        for app in registered_apps {
            state.add_app_to_state(&app);
        }

        Ok(state)
    }
}

pub trait State {
    fn app_tables(&self, application: &str) -> AppTable;

    fn app_key(&self, application: &str) -> PublicKey;

    fn apps(&self) -> Vec<&String>;

    fn db(&self) -> &Database;

    fn private(&self) -> &PrivateState;

    fn keys(&self) -> &impl KeyState<2>;

    fn rng(&self) -> StdRng {
        StdRng::from_entropy()
    }
}

impl<T: GovernorState> State for T {
    fn app_tables(&self, application: &str) -> AppTable {
        self.app_tables(application)
    }

    fn app_key(&self, application: &str) -> PublicKey {
        self.app_key(application)
    }

    fn db(&self) -> &Database {
        self.db()
    }

    fn private(&self) -> &PrivateState {
        self.private()
    }

    fn apps(&self) -> Vec<&String> {
        self.apps()
    }

    fn keys(&self) -> &impl KeyState<2> {
        self.keys()
    }
}

impl<const SN: usize, T: GovernorKeyState<SN>> KeyState<SN> for T {
    fn opaque(&self) -> &str {
        self.opaque()
    }

    fn sess_veri_keys(&self) -> &[SessionKey; SN] {
        self.sess_veri_keys()
    }

    fn eph_veri_keys(&self, application: &str) -> (Vec<EphemeralKey>, usize) {
        self.eph_veri_keys(application)
    }

    fn ephemeral_key(&self, application: &str) -> EphemeralKey {
        self.ephemeral_key(application)
    }
}

pub trait GovernorKeyState<const SN: usize> {
    fn opaque(&self) -> &str;

    fn sess_veri_keys(&self) -> &[SessionKey; SN];

    fn session_key(&self) -> &SessionKey {
        self.sess_veri_keys().last().unwrap()
    }

    fn register_application(&mut self, application: &str, amount_valid: Option<usize>);

    fn rotate_session_keys(&mut self, key: SessionKey);

    // Moves all keys from the invalidated key to the end one place left, and puts the new key at the end. If the key does not exist, it must call rotate_session_keys.
    fn invalidate_session_key(&mut self, key_to_invalidate: &SessionKey, new_key: SessionKey);

    fn update_ephemeral_time(&mut self);

    fn rotate_opaque(&mut self) {
        todo!()
    }

    fn from_init(key_init: KeyInitState<SN>) -> Self;

    fn eph_veri_keys(&self, application: &str) -> (Vec<EphemeralKey>, usize);

    fn ephemeral_key(&self, application: &str) -> EphemeralKey;
}

pub trait KeyState<const SN: usize> {
    fn opaque(&self) -> &str;

    fn sess_veri_keys(&self) -> &[SessionKey; SN];

    fn session_key(&self) -> &SessionKey {
        self.sess_veri_keys().last().unwrap()
    }

    fn eph_veri_keys(&self, application: &str) -> (Vec<EphemeralKey>, usize);

    fn ephemeral_key(&self, application: &str) -> EphemeralKey;
}

#[derive(Clone)]
struct AppSecret {
    base_seed: [u8; 32],
    amount_valid: usize,
}

#[derive(Clone)]
pub struct CoreKeyState<const SN: usize> {
    valid_session_keys: [SessionKey; SN],
    ephemeral_secret: [u8; 32],
    ephemeral_time: u64,
    app_secrets: HashMap<String, AppSecret>,
    opaque: String,
}

fn create_app_secret(
    base_secret: &[u8; 32],
    application: &str,
    amount_valid: Option<usize>,
) -> AppSecret {
    let mut hasher = Sha256::new();

    hasher.update(application.as_bytes());
    hasher.update(base_secret.clone());

    let base_seed: [u8; 32] = hasher.finalize().into();

    let amount_valid = amount_valid.unwrap_or(2);

    AppSecret {
        amount_valid,
        base_seed,
    }
}

impl<const SN: usize> GovernorKeyState<SN> for CoreKeyState<SN> {
    fn opaque(&self) -> &str {
        &self.opaque
    }

    fn eph_veri_keys(&self, application: &str) -> (Vec<EphemeralKey>, usize) {
        let app_secret = self.app_secrets.get(application).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        (
            EphemeralKey::last(
                app_secret.base_seed.clone(),
                now,
                self.ephemeral_time,
                app_secret.amount_valid,
            ),
            app_secret.amount_valid,
        )
    }

    fn sess_veri_keys(&self) -> &[SessionKey; SN] {
        &self.valid_session_keys
    }

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

    fn update_ephemeral_time(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.ephemeral_time = now;
    }

    fn register_application(&mut self, application: &str, amount_valid: Option<usize>) {
        let base_secret = &self.ephemeral_secret;

        let app_secret = create_app_secret(base_secret, application, amount_valid);

        self.app_secrets.insert(application.to_owned(), app_secret);
    }

    fn from_init(key_init: KeyInitState<SN>) -> Self {
        Self {
            valid_session_keys: key_init.session_keys,
            ephemeral_secret: key_init.ephemeral_secret,
            opaque: key_init.opaque,
            ephemeral_time: key_init.ephemeral_time,
            app_secrets: HashMap::new(),
        }
    }

    fn ephemeral_key(&self, application: &str) -> EphemeralKey {
        let app_secret = self.app_secrets.get(application).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        EphemeralKey::compute(app_secret.base_seed.clone(), now, self.ephemeral_time)
    }
}

#[derive(Clone)]
pub struct PrivateState {
    // If this is leaked, passwords are not immediately at risk. However, it does allow another server to impersonate this one as it is now
    // able to verify user passwords (if it also has their password files).
    pub opaque: String,
    // Leaking this is catastrophic, as this allows an attacker to create verified sessions at will which are accepted by this server.
    pub session: SessionKey,
    // Leaking this is catastrophic, as it allows attackers to impersonate applications, allowing them to query and modify users at will.
    pub private: Key,
}

pub struct KeyInitState<const SN: usize> {
    pub opaque: String,
    pub ephemeral_secret: [u8; 32],
    pub session_keys: [SessionKey; SN],
    pub ephemeral_time: u64,
}

/// CoreState is a single-threaded implementation of State. See `tiauth-server`'s ServerState for a multi-threaded impelementation.
#[derive(Clone)]
pub struct CoreState {
    pub tables: HashMap<String, TableStore>,
    pub app_keys: HashMap<String, PublicKey>,
    pub db: Arc<Database>,
    pub private: PrivateState,
    pub key_state: CoreKeyState<2>,
}

fn register_application_tables(map: &mut HashMap<String, TableStore>, application: &str) {
    let session_name = format!("{}:sessions", application);
    let user_name = format!("{}:users", application);
    let state_name = format!("{}:ephemeral", application);

    map.insert(
        application.to_owned(),
        (session_name, user_name, state_name),
    );
}

impl GovernorState for CoreState {
    type Readonly = CoreState;

    fn add_app_to_state(&mut self, application: &Application) {
        register_application_tables(&mut self.tables, &application.name);

        self.app_keys
            .insert(application.name.clone(), application.public_key());
    }

    fn app_tables(&self, application: &str) -> AppTable {
        let store = self.tables.get(application).unwrap();
        AppTable::new(store)
    }

    fn db(&self) -> &Database {
        &self.db
    }

    fn private(&self) -> &PrivateState {
        &self.private
    }

    fn from_init(init_state: InitState<2>) -> Self {
        Self {
            tables: HashMap::new(),
            app_keys: HashMap::new(),
            db: Arc::new(init_state.db),
            private: init_state.private,
            key_state: CoreKeyState::from_init(init_state.key_init),
        }
    }

    fn app_key(&self, application: &str) -> PublicKey {
        self.app_keys.get(application).unwrap().clone()
    }

    fn remove_app_from_state(&mut self, application: &str) {
        self.app_keys.remove(application);
        self.tables.remove(application);
    }

    fn apps(&self) -> Vec<&String> {
        self.tables.keys().collect()
    }

    fn keys(&self) -> &impl GovernorKeyState<2> {
        &self.key_state
    }

    fn keys_mut(&mut self) -> &mut impl GovernorKeyState<2> {
        &mut self.key_state
    }
}

pub struct InitState<const SN: usize> {
    pub db: Database,
    pub private: PrivateState,
    pub key_init: KeyInitState<SN>,
}

impl<const SN: usize> InitState<SN> {
    fn init<P: AsRef<Path>>(db_path: P, now: u64) -> Result<Self, DbError> {
        let db = open_db(db_path)?;
        let mut rng = StdRng::from_entropy();
        let private = init_private_state(&db, &mut rng)?;
        let key_init = init_key_state(&db, &mut rng, now)?;

        Ok(Self {
            db,
            private,
            key_init,
        })
    }
}

const fn gen_range_array<const N: usize>() -> [usize; N] {
    let mut res = [0usize; N];

    let mut i = 0;
    while i < N {
        res[i] = i;
        i += 1;
    }

    res
}

fn init_key_state<const SN: usize>(
    db: &Database,
    rng: &mut StdRng,
    now: u64,
) -> Result<KeyInitState<SN>, DbError> {
    let write_txn = db.begin_write()?;

    let (opaque, session_keys, private, ephemeral_secret, ephemeral_time) = {
        let mut table = write_txn.open_table(SERVER)?;
        let setup = table.get("opaque_setup")?.map(|a| a.value());

        let setup = if let Some(setup) = setup {
            setup
        } else {
            let setup = create_setup();
            table.insert("opaque_setup", setup.clone())?;
            setup
        };

        let range_arr: [usize; SN] = const { gen_range_array() };

        let session_keys: Result<Vec<Option<SessionKey>>, DbError> = (0..SN)
            .map(|i| {
                let key_name = format!("session_key_{}", i);
                let session_key = table.get(key_name.as_str())?.map(|a| a.value());
                if let Some(session_key) = session_key {
                    Ok(Some(load_session_key(&session_key)))
                } else {
                    let session_key = create_session_key(rng);
                    let saved_session_key = save_session_key(&session_key);
                    table.insert(key_name.as_str(), saved_session_key.session)?;
                    Ok(Some(session_key))
                }
            })
            .collect();

        let mut session_keys = session_keys?;

        let session_keys: [SessionKey; SN] = range_arr.map(|i| session_keys[i].take().unwrap());

        let private_key = table.get("private_key")?.map(|a| a.value());

        let keypair = if let Some(private_key) = private_key {
            load_key(&private_key).unwrap()
        } else {
            let keypair = create_key();
            let saved_private_key = save_private_key(&keypair);

            table.insert("private_key", saved_private_key)?;
            keypair
        };

        let ephemeral_secret = table.get("ephemeral_secret")?.map(|a| a.value());

        let ephemeral_secret = if let Some(ephemeral_secret) = ephemeral_secret {
            let secret_bytes = b64::URL_SAFE_NO_PAD.decode(ephemeral_secret).unwrap();
            assert_eq!(secret_bytes.len(), 32);
            let mut ephemeral_secret = [0u8; 32];
            ephemeral_secret.copy_from_slice(&secret_bytes);
            ephemeral_secret
        } else {
            let mut ephemeral_secret = [0u8; 32];
            rng.fill_bytes(&mut ephemeral_secret);
            table.insert(
                "ephemeral_secret",
                b64::URL_SAFE_NO_PAD.encode(&ephemeral_secret),
            )?;
            ephemeral_secret
        };

        let ephemeral_time = table.get("ephemeral_time")?.map(|a| a.value());

        let ephemeral_time = if let Some(ephemeral_time) = ephemeral_time {
            (&ephemeral_time).parse().unwrap()
        } else {
            table.insert("ephemeral_time", now.to_string())?;
            now
        };

        (
            setup,
            session_keys,
            keypair,
            ephemeral_secret,
            ephemeral_time,
        )
    };
    write_txn.commit()?;

    Ok(KeyInitState {
        opaque,
        session_keys,
        ephemeral_secret,
        ephemeral_time,
    })
}

fn init_private_state(db: &Database, rng: &mut StdRng) -> Result<PrivateState, DbError> {
    let write_txn = db.begin_write()?;

    let (opaque, session, private) = {
        let mut table = write_txn.open_table(SERVER)?;
        let setup = table.get("opaque_setup")?.map(|a| a.value());

        let setup = if let Some(setup) = setup {
            setup
        } else {
            let setup = create_setup();
            table.insert("opaque_setup", setup.clone())?;
            setup
        };

        let session_key = table.get("session_key")?.map(|a| a.value());

        let session_key = if let Some(session_key) = session_key {
            load_session_key(&session_key)
        } else {
            let session_key = create_session_key(rng);
            let saved_session_key = save_session_key(&session_key);

            table.insert("session_key", saved_session_key.session)?;
            session_key
        };

        let private_key = table.get("private_key")?.map(|a| a.value());

        let keypair = if let Some(private_key) = private_key {
            load_key(&private_key).unwrap()
        } else {
            let keypair = create_key();
            let saved_private_key = save_private_key(&keypair);

            table.insert("private_key", saved_private_key)?;
            keypair
        };

        (setup, session_key, keypair)
    };
    write_txn.commit()?;

    Ok(PrivateState {
        opaque,
        session,
        private,
    })
}

pub fn write_app_to_db(db: &Database, application: &Application) -> Result<(), DbError> {
    let app_buf = encode::to_vec_named(&application).unwrap();

    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(APPS)?;
        table
            .insert(application.name.as_str(), app_buf.as_slice())
            .unwrap();
    }
    write_txn.commit()?;

    Ok(())
}

pub fn remove_app_from_db(
    db: &Database,
    application: &str,
    tables: AppTable,
) -> Result<(), DbError> {
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(APPS)?;
        table.remove(application)?;

        for t in tables.all() {
            // This is a fake definition with wrong types, but the types don't have to match to delete the table
            let definition: TableDefinition<String, String> = TableDefinition::new(&t);
            write_txn.delete_table(definition)?;
        }
    }
    write_txn.commit()?;

    Ok(())
}

fn get_apps(db: &Database) -> Result<Vec<Application>, DbError> {
    let write_txn = db.begin_write()?;
    let apps = {
        let table = write_txn.open_table(APPS)?;

        let mut apps = Vec::new();

        for app_entry in table.iter()? {
            let (_, app_bytes) = app_entry?;

            let app_bytes = app_bytes.value();

            let app: Application = decode::from_read(app_bytes).unwrap();

            apps.push(app);
        }

        apps
    };

    write_txn.commit()?;

    Ok(apps)
}

#[cfg(feature = "test")]
pub mod test_util {
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
        tables: HashMap<String, TableStore>,
        app_keys: HashMap<String, Key>,
        app_public_keys: HashMap<String, PublicKey>,
        db: Database,
        private: PrivateState,
        key_state: CoreKeyState<2>,
    }

    // pub struct TestKeyState {
    //     valid_session_keys: [SessionKey; 2],
    //     ephemeral_secret: [u8; 32],
    //     ephemeral_time: u64,
    //     app_secrets: HashMap<String, AppSecret>,
    //     opaque: String
    // }

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

    impl TestState {
        pub fn setup_test(applications: Vec<&str>) -> Self {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - (86400 * 15);

            let InitState {
                db,
                private,
                key_init,
            } = InitState::init(tmp.path(), now).unwrap();

            let mut tables: HashMap<String, TableStore> = HashMap::new();
            let mut app_keys: HashMap<String, Key> = HashMap::new();
            let mut app_public_keys: HashMap<String, PublicKey> = HashMap::new();

            let mut app_secrets: HashMap<String, AppSecret> = HashMap::new();

            for app_name in applications {
                let (key, app) = create_app(app_name);

                // TODO? check if re-enable
                //write_app_to_db(&db, &app).unwrap();

                // TODO app secrets
                register_application_tables(&mut tables, app_name);
                app_public_keys.insert(app_name.to_owned(), key.to_public_key());
                app_keys.insert(app_name.to_owned(), key);

                let app_secret = create_app_secret(&key_init.ephemeral_secret, app_name, Some(2));

                app_secrets.insert(app_name.to_owned(), app_secret);
            }

            let key_state = CoreKeyState {
                valid_session_keys: key_init.session_keys,
                ephemeral_secret: key_init.ephemeral_secret,
                ephemeral_time: key_init.ephemeral_time,
                app_secrets,
                opaque: key_init.opaque,
            };

            Self {
                db,
                private,
                tables,
                app_keys,
                app_public_keys,
                key_state,
            }
        }

        pub fn proof_key(&self, application: &str) -> &Key {
            self.app_keys.get(application).unwrap()
        }
    }

    impl GovernorState for TestState {
        type Readonly = TestState;

        fn add_app_to_state(&mut self, _: &Application) {
            unimplemented!("Do not use this function for TestState. Register through `setup_test`.")
        }

        fn app_tables(&self, application: &str) -> AppTable {
            let store = self.tables.get(application).unwrap();
            AppTable::new(store)
        }

        fn db(&self) -> &Database {
            &self.db
        }

        fn private(&self) -> &PrivateState {
            &self.private
        }

        fn from_init(_: InitState<2>) -> Self {
            unimplemented!("Do not use this function for TestState! Use `setup_test`.")
        }

        fn app_key(&self, application: &str) -> PublicKey {
            self.app_public_keys.get(application).unwrap().clone()
        }

        fn setup<P: AsRef<Path>>(_: P, _: u64) -> Result<Self, DbError>
        where
            Self: Sized,
        {
            unimplemented!("Do not use this function for TestState!")
        }

        fn remove_app_from_state(&mut self, _: &str) {
            unimplemented!("Do not use this function for TestState!")
        }

        fn apps(&self) -> Vec<&String> {
            self.tables.keys().collect()
        }

        fn keys(&self) -> &impl GovernorKeyState<2> {
            &self.key_state
        }

        fn keys_mut(&mut self) -> &mut impl GovernorKeyState<2> {
            &mut self.key_state
        }
    }
}
