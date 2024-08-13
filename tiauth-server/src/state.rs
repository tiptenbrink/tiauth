use ambassador::{delegatable_trait, delegate_to_methods, Delegate};
use tiauth_core::{ambassador_impl_AppState, ambassador_impl_CounterState, ambassador_impl_DriverState, CounterState};
use redb::Database;
use tiauth_core::state_impl::AppStateImpl;
use tiauth_core::versionmap::{VersionMap, VersionMapView};
use parking_lot::{RwLock, RwLockReadGuard};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc};
use tiauth_core::crypto::PublicKey;
// use tiauth_core::state_impl::{AppTable, PrivateState, TableStore};
// use tiauth_core::{CoreKeyState, CoreState, KeyState};
use tiauth_core::{AppState, KeyState, State, Store, DriverState};

#[derive(Clone)]
pub struct ServerState {
    states: VersionMapView<String, RwLock<AppStateImpl>>
}

impl ServerState {
    pub fn app(&self, application: &str) -> RwLockReadGuard<'_, AppStateImpl> {
        let lock = self.states.get(application).unwrap().unwrap();
        lock.read()
    }
}

// impl<'a> State for StateWrapper<'a> {}

// impl<'a> AppState for StateWrapper<'a> {
//     fn application(&self) -> &str {
//         self.0.application()
//     }

//     fn public_key(&self) -> &PublicKey {
//         self.0.public_key()
//     }

//     fn store(&self) -> &Store {
//         self.0.store()
//     }

//     fn keys(&self) -> &impl KeyState<2> {
//         self.0.keys()
//     }
// }

// impl<'a> AppState for StateWrapper<'a> {

// struct ServerState {
//     rcvrs: Vec<(String, Receiver<Arc<AppStateImpl>>)>
// }

// impl ServerState {
//     async fn state(&self, app: &str) -> Arc<impl AppState> {
//         for (r_app, r) in &self.rcvrs {
//             if app == r_app.as_str() {
//                 return r.borrow().clone()
//             }
//         }
//         unimplemented!("Implement receiver add!")
//     }
// }

// #[derive(Clone)]
// pub struct ServerState {
//     tables: Arc<HashMap<String, TableStore>>,
//     db: Arc<Database>,
//     private: Arc<PrivateState>,
//     app_keys: Arc<HashMap<String, PublicKey>>,
//     key_state: Arc<CoreKeyState<2>>
// }

// impl State for ServerState {
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
//         self.app_keys.get(application).unwrap().clone()
//     }

//     fn apps(&self) -> Vec<&String> {
//         self.tables.keys().collect()
//     }
    
//     fn keys(&self) -> &impl KeyState<2> {
//         self.key_state.as_ref()
//     }
// }

// pub trait ReadonlyState {
//     type Readonly;

//     fn readonly_state(&self) -> Self::Readonly;
// }

// impl ReadonlyState for CoreState {
//     type Readonly = ServerState;

//     fn readonly_state(&self) -> Self::Readonly {
//         let Self {
//             tables,
//             db,
//             private,
//             app_keys,
//             key_state
//         } = self.clone();

//         Self::Readonly {
//             tables: Arc::new(tables),
//             db,
//             private: Arc::new(private),
//             app_keys: Arc::new(app_keys),
//             key_state: Arc::new(key_state)
//         }
//     }
// }
