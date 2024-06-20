use std::path::Path;
use bytes::Bytes;
use axum::{extract::{Json, State as ExtractState}, http::request, routing::{get, post}, Router};
use tiauth_core::{
    api::{Application, State},
    crypto::{create_key, load_key, save_key},
};
use crate::functions::{PakeFinishRequest, PakeRequest, PakeResponse};
use crate::functions;
use crate::admin;
use crate::state::ServerState;

async fn start_register(ExtractState(state): ExtractState<ServerState>, Json(request): Json<PakeRequest>) -> Json<PakeResponse> { 
    Json(functions::start_register(&state, request).await)
}

async fn register_finish(ExtractState(state): ExtractState<ServerState>, Json(request): Json<PakeFinishRequest>) { 
    functions::register_finish(&state, request).await
}

async fn admin_get_users_encoded(ExtractState(state): ExtractState<ServerState>, body: Bytes) -> Vec<u8> { 
    admin::get_users_encoded(&state, body).await
}

pub fn create_router<S, P>(db_path: P) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    P: AsRef<Path>,
{
    let mut state = ServerState::setup(db_path).unwrap();

    let public_key_pem = "-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoAYLYqlDb45JjRtqllCk3MVUWbodjBVY3Lkf+DAZOJIhWPt4ew
VfAwioXbWygeZ6l1jVRqz5l+/Q8A
-----END PUBLIC KEY-----".to_owned();

    let app = Application::new(public_key_pem, "some_app");

    state.register_application(&app, true).unwrap();

    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/register/start", post(start_register))
        .route("/register/finish", post(register_finish))
        .route("/admin/users", post(admin_get_users_encoded))
        .with_state(state)
}
