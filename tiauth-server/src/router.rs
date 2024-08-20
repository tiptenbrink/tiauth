use crate::admin;
use crate::functions;
use crate::model::*;
use crate::state::ServerState;
use axum::{
    async_trait,
    extract::{FromRequest, Json, Request, State as ExtractState},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
use tiauth_core::State;
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

async fn proof_token<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Json(request): Json<ProofTokenRequest>,
) -> Json<ProofTokenResponse> {
    Json(
        state
            .app(request.application.clone(), move |state| {
                functions::proof_token(state, request)
            })
            .await
            .unwrap(),
    )
}

async fn start_register<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Json(request): Json<PakeRequest>,
) -> Json<StartRegisterResponse> {
    Json(
        state
            .app(request.application.clone(), move |state| {
                functions::start_register(state, request)
            })
            .await
            .unwrap(),
    )
}

async fn register_finish<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Json(request): Json<RegisterFinishRequest>,
) -> Result<(), ErrorResponse> {
    state
        .app(request.application.clone(), move |state| {
            functions::register_finish(state, request);
        })
        .await
        .unwrap();

    Ok(())
}

async fn start_login<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Json(request): Json<PakeRequest>,
) -> Json<StartLoginResponse> {
    Json(
        state
            .app(request.application.clone(), move |state| {
                functions::start_login(state, request)
            })
            .await
            .unwrap(),
    )
}

async fn login_session<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Json(request): Json<LoginFinishRequest>,
) -> Json<SessionResponse> {
    Json(
        state
            .app(request.application.clone(), move |state| {
                functions::login_session(state, request)
            })
            .await
            .unwrap(),
    )
}

async fn admin_get_users_encoded<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Json(request): Json<GetUsers>,
) -> Vec<u8> {
    state
        .app(request.application.clone(), move |state| {
            admin::get_users_encoded(state, request)
        })
        .await
        .unwrap()
}

pub fn create_router<S: State, Z: Clone + Send + Sync + 'static>(
    state: ServerState<S>,
) -> Router<Z> {
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/register/start", post(start_register))
        .route("/register/finish", post(register_finish))
        .route("/login/start", post(start_login))
        .route("/login/session", post(login_session))
        .route("/admin/users", post(admin_get_users_encoded))
        .route("/proof/token", post(proof_token))
        .with_state(state)
        .layer((TimeoutLayer::new(Duration::from_secs(15)),))
}
