use crate::admin;
use crate::functions;
use crate::state::ServerState;
use crate::{
    admin::GetUsers,
    functions::{PakeFinishRequest, PakeRequest, PakeResponse},
};
use axum::{
    async_trait,
    extract::{FromRequest, Json, Request, State as ExtractState},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::Path;
use tiauth_core::{Application, State};

#[derive(Debug, Clone, Copy, Default)]
pub struct MessagePack<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for MessagePack<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ErrorResponse;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|r| ErrorResponse {
                error: "bytes_extractor".to_owned(),
                description: r.to_string(),
            })?;
        Self::from_bytes(&bytes)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ErrorResponse {
    error: String,
    description: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

impl<T> MessagePack<T>
where
    T: DeserializeOwned,
{
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorResponse> {
        let inner: Result<T, rmp_serde::decode::Error> = rmp_serde::from_slice(bytes);
        let inner = match inner {
            Ok(inner) => inner,
            Err(err) => {
                return Err(ErrorResponse {
                    error: "msgpack_decode".to_owned(),
                    description: err.to_string(),
                })
            }
        };
        Ok(Self(inner))
    }
}

async fn start_register(
    ExtractState(state): ExtractState<ServerState>,
    Json(request): Json<PakeRequest>,
) -> Json<PakeResponse> {
    Json(functions::start_register(&state, request).await)
}

async fn register_finish(
    ExtractState(state): ExtractState<ServerState>,
    Json(payload): Json<PakeFinishRequest>,
) -> Result<(), ErrorResponse> {
    functions::register_finish(&state, payload).await;

    Ok(())
}

async fn admin_get_users_encoded(
    ExtractState(state): ExtractState<ServerState>,
    Json(payload): Json<GetUsers>,
) -> Vec<u8> {
    admin::get_users_encoded(&state, payload).await
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
-----END PUBLIC KEY-----"
        .to_owned();

    let app = Application::new(public_key_pem, "some_app");

    state.register_application(&app, true).unwrap();

    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/register/start", post(start_register))
        .route("/register/finish", post(register_finish))
        .route("/admin/users", post(admin_get_users_encoded))
        .with_state(state)
}
