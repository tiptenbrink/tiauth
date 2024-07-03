#![allow(dead_code)]

pub mod crypto;
mod data;
mod error;
mod util;
mod proof;

#[cfg(feature = "action")]
mod ops;
#[cfg(feature = "action")]
mod state;
#[cfg(feature = "action")]
mod store;

pub use crate::data::ActionType;
pub use crate::data::Application;
pub use crate::data::Claims;
//pub use crate::data::Proof;
pub use crate::data::{BytePacked, ByteOwned, ByteSerial};
pub use crate::data::Target;
pub use crate::data::TargetList;

#[cfg(feature = "action")]
pub mod state_impl {
    pub use crate::state::InitState;
    pub use crate::state::PrivateState;
    pub use crate::store::AppTable;
    pub use crate::store::MapTables;
    pub use crate::store::TableStore;
}

#[cfg(feature = "action")]
mod action {
    pub use crate::ops::admin;
    pub use crate::ops::verify;
    pub use crate::ops::register;
    pub use crate::state::State;

    pub use crate::store::Tables;
}
#[cfg(feature = "action")]
pub use action::*;

#[cfg(feature = "app")]
pub mod app;

#[cfg(feature = "test")]
pub mod test {
    pub use super::ops::login::test_util::*;
    pub use super::ops::verify::test_util::*;
    pub use super::ops::register::test_util::*;
    pub use super::state::test_util::*;
}
