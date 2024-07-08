#![allow(dead_code)]

use std::sync::Arc;

use reqwest::Url;
use tiauth_core::app::{create_set_claims_proof, ProofBaseView};
use tiauth_core::crypto::{load_key, Key};
use tiauth_core::error::OneOfTo;
use tiauth_core::{BytePacked, Claims, Proof, SessionClaims};
use tiauth_core::encoded::Encoded;
use tiauth_server::model::*;
use opaque_borink::Error as OpqError;
use opaque_borink::client::{client_login, client_login_finish, client_register, client_register_finish};
use terrors::OneOf;
use tokio::runtime::{self, Handle, Runtime};


#[derive(Clone)]
pub struct ApplicationLogin {
    user_id: String,
    all_claims: Option<bool>,
    requested_claims: Option<Vec<String>>
}

impl ApplicationLogin {
    pub fn prepare(user_id: &str, all_claims: Option<bool>, requested_claims: Option<Vec<String>>) -> Self {
        ApplicationLogin { user_id: user_id.to_owned(), all_claims, requested_claims }
    }
}

pub struct ApplicationRegister {
    user_id: String,
    claims_proof: Option<Encoded<Proof<Claims>>>
}

#[derive(Clone)]
pub struct AppClient {
    application: String,
    private_key: Key,
    proof_expiration: u64
}

impl AppClient {
    pub fn new(application: &str, private_key_pem: &str, proof_expiration: Option<u64>) -> Self {
        let key = load_key(private_key_pem).unwrap();

        Self {
            application: application.to_owned(),
            private_key: key,
            proof_expiration: proof_expiration.unwrap_or(1800)
        }
    }

    pub fn prepare_login(&self, user_id: &str, all_claims: Option<bool>, requested_claims: Option<Vec<String>>) -> ApplicationLogin {
        ApplicationLogin::prepare(user_id, all_claims, requested_claims)
    }

    pub fn prepare_register(&self, user_id: &str, set_claims: Option<&BytePacked<Claims>>) -> ApplicationRegister {
        let proof = if let Some(claims) = set_claims {
            let proof_base = ProofBaseView {
                key: &self.private_key,
                application: &self.application,
                expires_in: self.proof_expiration
            };

            Some(create_set_claims_proof(proof_base, user_id, claims))
        } else {
            None
        };

        ApplicationRegister { user_id: user_id.to_owned(), claims_proof: proof }
    }
}

pub struct UserClient {
    application: String,
    client: reqwest::Client,
    base_url: Url,
    handle: Arc<Handle>,
    runtime: Option<Runtime>
}

impl UserClient {
    /// Creates a new UserClient. If called from an asynchronous context, it will re-use that context's runtime. However, if that
    /// runtime is not multi-threaded, problems can occur with network requests. If called from a non-async context, it will create
    /// its own runtime that is shutdown when UserClient is dropped. Use the `blocking` variants in that case.
    pub fn new(application: &str, tiauth_url: &str) -> Self {
        let client = reqwest::ClientBuilder::new().build().unwrap();

        let tiauth_url = if !tiauth_url.ends_with("/") {
            format!("{}/", tiauth_url)
        } else {
            tiauth_url.to_owned()
        };
        let url = Url::try_from(tiauth_url.as_str()).unwrap();

        let current = Handle::try_current();

        let runtime = if current.is_err() {
            Some(runtime::Builder::new_multi_thread().enable_all().build().unwrap())
        } else {
            None
        };

        let handle = if let Ok(handle) = current {
            Arc::new(handle)
        } else {
            Arc::new(runtime.as_ref().unwrap().handle().clone())
        };

        Self {
            application: application.to_owned(),
            client,
            base_url: url,
            runtime,
            handle
        }
    }

    pub fn from_server(server_client: &AppClient, tiauth_url: &str) -> Self {
        Self::new(&server_client.application, tiauth_url)
    }

    fn at(&self, path: &str) -> Url {
        self.base_url.join(path).unwrap()
    }

    pub fn login_user_blocking(&self, app_login: ApplicationLogin, password: &str) -> Result<String, OneOf<(OpqError,)>> {
        self.handle.block_on(self.login_user(app_login, password))
    }

    pub async fn login_user(&self, app_login: ApplicationLogin, password: &str) -> Result<String, OneOf<(OpqError,)>> {
        let (start_request, state) = client_login(password).to_one_of()?;

        let pake_request = PakeRequest { application: self.application.clone(), opaque_request: start_request, user_id: app_login.user_id };

        let response = self.client.post(self.at("login/start"))
            .json(&pake_request).send().await.unwrap();

        let pake_response: PakeResponse = response.json().await.unwrap();

        let (finish_request, secret) = client_login_finish(&state, password, &pake_response.opaque_response)?;

        let finish_request = LoginFinishRequest {
            application: self.application.clone(),
            opaque_request: finish_request,
            start_nonce: pake_response.start_nonce,
            pake_secret: secret,
            all_claims: app_login.all_claims,
            requested_claims: app_login.requested_claims,
        };

        let response = self.client.post(self.at("login/session"))
            .json(&finish_request).send().await.unwrap();

        assert!(response.status() == 200);

        let session_response: SessionResponse = response.json().await.unwrap();

        Ok(session_response.session)
    }

    pub fn register_user_blocking(&self, app_register: ApplicationRegister, password: &str) -> Result<(), OneOf<(OpqError,)>> {
        // Async support in PyO3 and other places is not fully mature, so we just block
        // We still use reqwest/tokio so in the future when support is better we can easily migrate
        self.handle.block_on(self.register_user(app_register, password))
    }

    pub async fn register_user(&self, app_register: ApplicationRegister, password: &str) -> Result<(), OneOf<(OpqError,)>> {
        let (start_request, state) = client_register(password).to_one_of()?;

        let pake_request = PakeRequest { application: self.application.clone(), opaque_request: start_request, user_id: app_register.user_id };

        let response = self.client.post(self.at("register/start"))
            .json(&pake_request).send().await.unwrap();

        let pake_response: PakeResponse = response.json().await.unwrap();

        let finish_request = client_register_finish(&state, password, &pake_response.opaque_response)?;

        let finish_request = RegisterFinishRequest {
            application: self.application.clone(),
            opaque_request: finish_request,
            start_nonce: pake_response.start_nonce,
            claims_proof: app_register.claims_proof,
        };

        let response = self.client.post(self.at("register/finish"))
            .json(&finish_request).send().await.unwrap();

        assert!(response.status() == 200);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::env;

    use tokio::test as async_test;

    use super::*;

    const PRIVATE: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDOQyFXRlMQuTiQ9vFBc5qBXG1U2p79Qa0l40jO+Qlr/
-----END PRIVATE KEY-----";

    async fn register_user(application: &str, user_id: &str, password: &str) {
        let server_client = AppClient::new(application, PRIVATE, None);

        let register = server_client.prepare_register(user_id, None);

        let user_client = UserClient::new(application, "http://localhost:3000");

        user_client.register_user(register, password).await.unwrap();
    }

    fn register_user_blocking(application: &str, user_id: &str, password: &str) {
        let server_client = AppClient::new(application, PRIVATE, None);

        let register = server_client.prepare_register(user_id, None);

        let user_client = UserClient::new(application, "http://localhost:3000");

        user_client.register_user_blocking(register, password).unwrap();
    }

    #[async_test]
    async fn test_login() {
        let live = env::var("TIAUTH_LIVE").unwrap_or_else(|_| "".to_owned());
        if live != "1" {
            return;
        }

        let application = "some_app";
        let user_id = "some_user";

        register_user(&application, &user_id, "pass").await;

        let login = ApplicationLogin::prepare(user_id, Some(true), None);

        let user_client = UserClient::new(application, "http://localhost:3000");

        user_client.login_user(login, "pass").await.unwrap();
    }

    #[async_test]
    async fn test_register() {
        let live = env::var("TIAUTH_LIVE").unwrap_or_else(|_| "".to_owned());
        if live != "1" {
            return;
        }

        let application = "some_app";

        let user_id = "some_user";

        register_user(&application, &user_id, "pass").await;
        
    }

    #[test]
    fn test_blocking() {
        let live = env::var("TIAUTH_LIVE").unwrap_or_else(|_| "".to_owned());
        if live != "1" {
            return;
        }

        let application = "some_app";

        let user_id = "some_user";

        register_user_blocking(application, user_id, "pass");
        
        let login = ApplicationLogin::prepare(user_id, Some(true), None);

        let user_client = UserClient::new(application, "http://localhost:3000");

        user_client.login_user_blocking(login, "pass").unwrap();
    }
}