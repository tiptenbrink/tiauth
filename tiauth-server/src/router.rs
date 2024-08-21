use crate::admin;
use crate::functions;
use crate::model::*;
use crate::state::ServerState;
use axum::middleware;
use axum::middleware::Next;
use axum::Extension;
use axum::{
    async_trait,
    extract::{FromRequest, Json, Request, State as ExtractState},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::trace::DefaultMakeSpan;
use tower_http::trace::TraceLayer;
use tracing::debug;
use tracing::debug_span;
use tracing::Instrument;
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
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<ProofTokenRequest>,
) -> Json<ProofTokenResponse> {
    Json(
        state
            .app(request.application.clone(), request_id.id, move |state| {
                functions::proof_token(state, request)
            })
            .await
            .unwrap(),
    )
}

async fn start_register<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<PakeRequest>,
) -> Json<StartRegisterResponse> {
    Json(
        state
            .app(request.application.clone(), request_id.id, move |state| {
                functions::start_register(state, request)
            })
            .await
            .unwrap(),
    )
}

async fn register_finish<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<RegisterFinishRequest>,
) -> Result<(), ErrorResponse> {
    state
        .app(request.application.clone(), request_id.id, move |state| {
            functions::register_finish(state, request);
        })
        .await
        .unwrap();

    Ok(())
}

async fn start_login<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<PakeRequest>,
) -> Json<StartLoginResponse> {
    Json(
        state
            .app(request.application.clone(), request_id.id, move |state| {
                functions::start_login(state, request)
            })
            .await
            .unwrap(),
    )
}

async fn login_session<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<LoginFinishRequest>,
) -> Json<SessionResponse> {
    Json(
        state
            .app(request.application.clone(), request_id.id, move |state| {
                functions::login_session(state, request)
            })
            .await
            .unwrap(),
    )
}

async fn user_set_claims<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<SetClaimsRequest>,
) -> Result<(), ErrorResponse> {
    state
        .app(request.application.clone(), request_id.id, move |state| {
            functions::user_set_claims(state, request);
        })
        .await
        .unwrap();

    Ok(())
}

async fn admin_get_users_encoded<S: State>(
    ExtractState(state): ExtractState<ServerState<S>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<GetUsers>,
) -> Vec<u8> {
    state
        .app(request.application.clone(), request_id.id, move |state| {
            admin::get_users_encoded(state, request)
        })
        .await
        .unwrap()
}

fn uid() -> String {
    let mut rng = thread_rng();
    let random_string: String = (0..6)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    random_string
}

#[derive(Clone)]
struct RequestId { id: String }

async fn request_id(
    mut request: Request,
    next: Next,
) -> Response {
    let id = uid();
    let span = debug_span!("id", id=id);
    request.extensions_mut().insert(RequestId { id });
    
    let response = next.run(request).instrument(span).await;

    response
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
        .route("/user/claims/set", post(user_set_claims))
        .route("/admin/users", post(admin_get_users_encoded))
        .route("/proof/token", post(proof_token))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(request_id))
                .layer(
                    TraceLayer::new_for_http()
                    .on_response(
                        tower_http::trace::DefaultOnResponse::new()
                            .latency_unit(tower_http::LatencyUnit::Micros)
                    )
                )

            
        )
        //.layer((TimeoutLayer::new(Duration::from_secs(15)),))
}
