use redb::Database;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use tiauth_core::crypto::PublicKey;
use tiauth_core::state_impl::{AppTable, InitState, PrivateState, TableStore};
use tiauth_core::Application;
use tiauth_core::{State, Tables};

#[derive(Clone)]
pub struct ServerState {
    table_map: ServerTables,
    // pub app_keys: &'a mut HashMap<String, PublicKey>,
    db: Arc<Database>,
    private: Arc<PrivateState>,
    // TODO change to just arc and do writing only before app starts?
    app_keys: Arc<Mutex<HashMap<String, PublicKey>>>,
}

#[derive(Clone)]
pub struct ServerTables {
    tables: Arc<Mutex<HashMap<String, TableStore>>>,
}

impl ServerTables {
    fn new() -> Self {
        Self {
            tables: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Tables for ServerTables {
    fn register_application(&mut self, application: &str) {
        let session_name = format!("{}:sessions", application);
        let user_name = format!("{}:users", application);
        let state_name = format!("{}:ephemeral", application);

        self.tables.lock().unwrap().insert(
            application.to_owned(),
            (session_name, user_name, state_name),
        );
    }

    fn app(&self, application: &str) -> AppTable {
        AppTable::new(
            self.tables
                .lock()
                .unwrap()
                .get(application)
                .unwrap()
                .clone(),
        )
    }
}

impl State for ServerState {
    fn register_application_internal(&mut self, application: &Application) {
        self.table_map.register_application(&application.name);
        self.app_keys
            .lock()
            .unwrap()
            .insert(application.name.to_owned(), application.public_key());
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
        let db = Arc::new(init_state.db);
        let private = Arc::new(init_state.private);

        Self {
            db,
            private,
            table_map: ServerTables::new(),
            app_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn app_key(&self, application: &str) -> PublicKey {
        self.app_keys
            .lock()
            .unwrap()
            .get(application)
            .unwrap()
            .clone()
    }
}
