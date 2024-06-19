#![allow(dead_code)]

pub mod api;
pub mod crypto;
mod data;
mod error;
mod ops;
mod state;
mod util;

// 1 month
const EXPIRE_TIME: u64 = 30 * 24 * 60 * 60;
