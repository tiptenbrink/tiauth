//use crate::admin;
use crate::functions;
use crate::model::{
    LoginFinishRequest, PakeRequest, PakeResponse, RegisterFinishRequest, SessionResponse, GetUsers
};
use axum::{
    async_trait,
    extract::{FromRequest, Json, Request, State as ExtractState},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use blocking::unblock;
use bytes::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::state::{ServerState};
use std::ops::Deref;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

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
    
    Json(unblock(move || {
        let app_state = state.app(&request.application);        
        functions::start_register(app_state.deref(), request)
    }).await)
}

// async fn register_finish(
//     ExtractState(state): ExtractState<ServerState>,
//     Json(payload): Json<RegisterFinishRequest>,
// ) -> Result<(), ErrorResponse> {
//     functions::register_finish(&state, payload);

//     Ok(())
// }

// async fn start_login(
//     ExtractState(state): ExtractState<ServerState>,
//     Json(request): Json<PakeRequest>,
// ) -> Json<PakeResponse> {
//     Json(functions::start_login(&state, request))
// }

// async fn login_session(
//     ExtractState(state): ExtractState<ServerState>,
//     Json(payload): Json<LoginFinishRequest>,
// ) -> Json<SessionResponse> {
//     Json(functions::login_session(&state, payload))
// }

// async fn admin_get_users_encoded(
//     ExtractState(state): ExtractState<ServerState>,
//     Json(payload): Json<GetUsers>,
// ) -> Vec<u8> {
//     admin::get_users_encoded(&state, payload).await
// }

pub fn create_router<S>(state: ServerState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/register/start", post(start_register))
        // .route("/register/finish", post(register_finish))
        // .route("/login/start", post(start_login))
        // .route("/login/session", post(login_session))
        //.route("/admin/users", post(admin_get_users_encoded))
        .with_state(state)
        .layer((TimeoutLayer::new(Duration::from_secs(15)),))
}
