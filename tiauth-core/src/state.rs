#![allow(dead_code)]

use opaque_borink::create_setup;
use rand::rngs::StdRng;
use rand::SeedableRng;
use redb::{Database, Error as DbError, ReadableTable};
use rmp_serde::{decode, encode};
use std::collections::HashMap;
use std::path::Path;

use crate::crypto::{
    create_key, create_session_key, load_key, load_session_key, save_private_key, save_session_key,
    Key, PublicKey, SessionKey,
};
use crate::data::Application;
use crate::store::{open_db, MapTables, Tables, APPS, SERVER};
pub trait State {
    fn register_application_internal(&mut self, application: &Application);

    fn register_application(
        &mut self,
        application: &Application,
        save: bool,
    ) -> Result<(), DbError> {
        if save {
            write_app_to_db(self.db(), application)?;
        }

        self.register_application_internal(application);

        Ok(())
    }

    fn tables(&self) -> &impl Tables;

    fn app_key(&self, application: &str) -> PublicKey;

    fn db(&self) -> &Database;

    fn rng(&self) -> StdRng {
        StdRng::from_entropy()
    }

    fn private(&self) -> &PrivateState;

    fn from_init(init_state: InitState) -> Self;

    fn setup<P: AsRef<Path>>(db_path: P) -> Result<Self, DbError>
    where
        Self: Sized,
    {
        let mut state = Self::from_init(InitState::init(db_path)?);

        let registered_apps = get_apps(state.db())?;

        for app in registered_apps {
            state.register_application(&app, false)?;
        }

        Ok(state)
    }
}

pub struct PrivateState {
    pub opaque: String,
    pub session: SessionKey,
    pub private: Key,
}

/// CoreState is a single-threaded implementation of State. See `tiauth-server`'s ServerState for a multi-threaded impelementation.
pub struct CoreState {
    table_map: MapTables,
    app_keys: HashMap<String, PublicKey>,
    db: Database,
    private: PrivateState,
}

impl State for CoreState {
    fn register_application_internal(&mut self, application: &Application) {
        self.table_map.register_application(&application.name);
        self.app_keys
            .insert(application.name.clone(), application.public_key());
    }

    fn tables(&self) -> &impl Tables {
        &self.table_map
    }

    fn db(&self) -> &Database {
        &self.db
    }

    fn private(&self) -> &PrivateState {
        &self.private
    }

    fn from_init(init_state: InitState) -> Self {
        Self {
            table_map: MapTables::new(),
            app_keys: HashMap::new(),
            db: init_state.db,
            private: init_state.private,
        }
    }

    fn app_key(&self, application: &str) -> PublicKey {
        self.app_keys.get(application).unwrap().clone()
    }
}

pub struct InitState {
    pub db: Database,
    pub private: PrivateState,
}

impl InitState {
    fn init<P: AsRef<Path>>(db_path: P) -> Result<Self, DbError> {
        let db = open_db(db_path)?;
        let private = init_private_state(&db, &mut StdRng::from_entropy())?;

        Ok(Self { db, private })
    }
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
        table_map: MapTables,
        app_keys: HashMap<String, Key>,
        app_public_keys: HashMap<String, PublicKey>,
        db: Database,
        private: PrivateState,
    }

    impl TestState {
        pub fn setup_test(applications: Vec<&str>) -> Self {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            let InitState { db, private } = InitState::init(tmp.path()).unwrap();

            let mut table_map = MapTables::new();
            let mut app_keys: HashMap<String, Key> = HashMap::new();
            let mut app_public_keys: HashMap<String, PublicKey> = HashMap::new();

            for app_name in applications {
                let (key, app) = create_app(app_name);

                write_app_to_db(&db, &app).unwrap();

                table_map.register_application(app_name);
                app_public_keys.insert(app_name.to_owned(), key.to_public_key());
                app_keys.insert(app_name.to_owned(), key);
            }

            Self {
                db,
                private,
                table_map,
                app_keys,
                app_public_keys,
            }
        }

        pub fn proof_key(&self, application: &str) -> &Key {
            self.app_keys.get(application).unwrap()
        }
    }

    impl State for TestState {
        fn register_application_internal(&mut self, _application: &Application) {
            unimplemented!("Do not use this function for TestState. Register through `setup_test`.")
        }

        fn tables(&self) -> &impl Tables {
            &self.table_map
        }

        fn db(&self) -> &Database {
            &self.db
        }

        fn private(&self) -> &PrivateState {
            &self.private
        }

        fn from_init(_init_state: InitState) -> Self {
            unimplemented!("Do not use this function for TestState! Use `setup_test`.")
        }

        fn app_key(&self, application: &str) -> PublicKey {
            self.app_public_keys.get(application).unwrap().clone()
        }

        fn setup<P: AsRef<Path>>(_db_path: P) -> Result<Self, DbError>
        where
            Self: Sized,
        {
            unimplemented!("Do not use this function for TestState!")
        }
    }
}
