use ambassador::{delegatable_trait, delegate_to_methods, Delegate};
use blocking::unblock;
use tiauth_core::{CounterState, GovernorState};
use redb::Database;
use tiauth_core::state_impl::AppStateImpl;
use tiauth_core::appendonly::{AppendOnlyArcMap, MapView};
use parking_lot::{RwLock, RwLockReadGuard};
use tracing::debug_span;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc};
use tiauth_core::crypto::PublicKey;
// use tiauth_core::state_impl::{AppTable, PrivateState, TableStore};
// use tiauth_core::{CoreKeyState, CoreState, KeyState};
use tiauth_core::{AppState, KeyState, State, Store, DriverState};
use tokio::sync::watch::{self, Receiver, Sender};

pub struct GovernorServerState<S: GovernorState> {
    states: AppendOnlyArcMap<String, RwLock<S>>
}

impl<S: GovernorState> GovernorServerState<S> {
    pub fn new(capacity: usize) -> Self {
        Self {
            states: AppendOnlyArcMap::new(capacity)
        }
    }

    pub fn load_application(&mut self, state: S) {
        let previous = self.states.insert(state.application().to_owned(), RwLock::new(state)).unwrap();
        if previous.is_some() {
            panic!("Can only add each application once! Use the RwLock to modify it.")
        }
    }

    pub fn app_mut_blocking<T, F: FnOnce(&mut S) -> T>(&self, application: &str, f: F) -> Result<T, ApplicationNotFound> {
        let state = self.states.get(application).ok_or(ApplicationNotFound)?;
        Ok(f(state.write().deref_mut()))
    }

    pub async fn app_mut<T: Send + 'static, F: FnOnce(&mut S) -> T + Send + 'static>(self, application: String, f: F) -> Result<T, ApplicationNotFound> {
        unblock(move || self.app_mut_blocking(&application, f)).await
    }

    pub fn view(&self) -> ServerState<S> {
        ServerState { states: self.states.view() }
    }
}

pub struct ServerState<S: State> {
    states: MapView<String, RwLock<S>>
}

impl<S: State> Clone for ServerState<S> {
    fn clone(&self) -> Self {
        Self { states: self.states.clone() }
    }
}

#[derive(Debug)]
pub struct ApplicationNotFound;

// fn app<'a, 'b>(states: &'a States, receiver: &'a Receiver<States>, application: &str) -> Result<RwLockReadGuard<'a, AppStateImpl>, ApplicationNotFound>  {
//     let value = match states.get(application) {
//         Ok(Some(value)) => value,
//         // Since the application exists, it's fine that we have an old value
//         Err(Some(value)) => value,
//         // If we have an old value, the application might have been added, so we receive
//         Err(None) => {
//             return app(receiver.borrow().deref(), receiver, application)
//         },
//         Ok(None) => return Err(ApplicationNotFound),
//         _ => unreachable!()
//     };

//     Ok(value.read())
// }

// fn abcd<'a>(state: &'a mut ServerState, application: &str) -> Option<RwLockReadGuard<'a, AppStateImpl>> {
//     match state.states.get(application) {
//         Ok(Some(lock)) => return Some(lock.read()),
//         Err(Some(lock)) => return Some(lock.read()),
//         _ => None
//     }
// }

// enum AppResult {
//     Ok(ServerState),
//     Retry(ServerState),
//     NotFound
// }

// fn get_state(state: ServerState, application: &str) -> Result<RwLockReadGuard<'_, AppStateImpl>, ApplicationNotFound> {
//     loop {
//         match state.with_app(application) {
//             Ok(state) => 
//         }
//     }
// }

impl<S: State> ServerState<S> {

    pub fn app_blocking<T, F: FnOnce(&S) -> T>(self, application: &str, f: F) -> Result<T, ApplicationNotFound> {
        let span = debug_span!("app", application);
        let _enter = span.enter();
        match self.states.get(application) {
            Some(lock) => Ok(f(lock.read().deref())),
            None => Err(ApplicationNotFound)
        }
        
    }

    pub async fn app<T: Send + 'static, F: FnOnce(&S) -> T + Send + 'static>(self, application: String, f: F) -> Result<T, ApplicationNotFound> {
        unblock(move || {
            self.app_blocking(&application, f)
        }).await
    }

    // pub fn with_app(self, application: &str) -> AppResult {
    //     match self.states.get(application) {
    //         Err(None) => AppResult::Retry(Self { states: self.receiver.borrow().clone(), receiver: self.receiver.clone() }),
    //         Ok(None) => AppResult::NotFound,
    //         _ => AppResult::Ok(self)
    //     }
        
    // }

    // pub fn get(&self, application: &str) -> RwLockReadGuard<'_, AppStateImpl> {
    //     self.states.get(application).ok().unwrap().unwrap().read()
        
    //     // Now try one more time
    //     // match self.states.get(application) {
    //     //     Some(lock) => Ok(lock.read()),
    //     //     None => Err(ApplicationNotFound),
    //     // }
    //     // match self.states.get(application) {
    //     //     Ok(Some(lock)) => return Ok(lock.read()),
    //     //     Ok(None) => return Err(ApplicationNotFound),
    //     //     Err(Some(lock)) => return Ok(lock.read()),
    //     //     _ => ()
    //     // };
    // }

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
