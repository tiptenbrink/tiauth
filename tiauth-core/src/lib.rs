#![allow(dead_code)]

mod counter;
pub mod crypto;
mod data;
pub mod encoded;
pub mod error;
mod proof;
mod util;
pub mod versionmap;

#[cfg(feature = "action")]
mod ops;
#[cfg(feature = "action")]
mod state;
#[cfg(feature = "action")]
mod store;

pub use crate::data::Application;
pub use crate::data::Claims;
pub use crate::data::SessionClaims;
pub use crate::data::{ByteOwned, BytePacked, ByteSerial};
pub use crate::proof::ActionType;
pub use crate::proof::Target;
pub use crate::proof::TargetList;
pub use crate::proof::{Ephemeral, Proof, Session};

#[cfg(feature = "action")]
pub mod state_impl {
    // pub use crate::state::InitState;
    // pub use crate::state::PrivateState;
    // pub use crate::store::AppTable;
    // pub use crate::store::MapTables;
    // pub use crate::store::TableStore;
    //pub use crate::state::ServerStateImpl;
    pub use crate::state::AppStateImpl;
    //pub use crate::state::{OnceVec, OnceList};
}

#[cfg(feature = "action")]
mod _action {
    //pub use crate::ops::admin;
    pub use crate::ops::register;
    pub use crate::ops::login;
    pub use crate::ops::modify;
    
    // pub use crate::ops::verify;
    // pub use crate::state::CoreKeyState;
    // pub use crate::state::CoreState;
    // pub use crate::state::GovernorState;
    pub use crate::store::Store;
    pub use crate::state::CounterState;
    pub use crate::state::DriverState;
    pub use crate::state::AppState;
    pub use crate::state::KeyState;
    pub use crate::state::State;
    pub use crate::state::ServerState;
    pub use crate::state::ambassador_impl_AppState;
    pub use crate::state::ambassador_impl_DriverState;
    pub use crate::state::ambassador_impl_CounterState;
    // pub use crate::store::Tables;
}
#[cfg(feature = "action")]
pub use _action::*;

#[cfg(feature = "app")]
pub mod app;
#[cfg(feature = "test")]
pub mod test {
    //pub use super::ops::login::test_util::*;
    // pub use super::ops::register::test_util::*;
    // pub use super::ops::verify::test_util::*;
    pub use super::state::test_util::*;
}
