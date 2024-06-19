use std::path::Path;

use axum::{routing::get, Router};
use tiauth_core::{
    api::{Application, State},
    crypto::{create_key, save_key},
};

use crate::state::ServerState;

pub fn create_router<S, P>(db_path: P) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    P: AsRef<Path>,
{
    let mut state = ServerState::setup(db_path).unwrap();

    let key = create_key();

    let saved_key = save_key(&key);

    let public_key = saved_key.public;

    let app = Application::new(public_key, "some_app");

    state.register_application(&app, true).unwrap();

    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .with_state(state)
}
