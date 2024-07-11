use redb::Database;
use std::collections::HashMap;
use std::sync::Arc;
use tiauth_core::crypto::PublicKey;
use tiauth_core::state_impl::{AppTable, PrivateState, TableStore};
use tiauth_core::{CoreKeyState, CoreState, KeyState};
use tiauth_core::State;

#[derive(Clone)]
pub struct ServerState {
    tables: Arc<HashMap<String, TableStore>>,
    db: Arc<Database>,
    private: Arc<PrivateState>,
    app_keys: Arc<HashMap<String, PublicKey>>,
    key_state: Arc<CoreKeyState<2>>
}

impl State for ServerState {
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

    fn app_key(&self, application: &str) -> PublicKey {
        self.app_keys.get(application).unwrap().clone()
    }

    fn apps(&self) -> Vec<&String> {
        self.tables.keys().collect()
    }
    
    fn keys(&self) -> &impl KeyState<2> {
        self.key_state.as_ref()
    }
}

pub trait ReadonlyState {
    type Readonly;

    fn readonly_state(&self) -> Self::Readonly;
}

impl ReadonlyState for CoreState {
    type Readonly = ServerState;

    fn readonly_state(&self) -> Self::Readonly {
        let Self {
            tables,
            db,
            private,
            app_keys,
            key_state
        } = self.clone();

        Self::Readonly {
            tables: Arc::new(tables),
            db,
            private: Arc::new(private),
            app_keys: Arc::new(app_keys),
            key_state: Arc::new(key_state)
        }
    }
}
