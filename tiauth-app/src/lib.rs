#![allow(dead_code)]

use reqwest::Url;
use tiauth_core::error::OneOfTo;
use tiauth_core::SessionClaims;
use tiauth_server::model::*;
use opaque_borink::Error as OpqError;
use opaque_borink::client::{client_login, client_login_finish, client_register, client_register_finish};
use terrors::OneOf;

struct ApplicationLogin {
    user_id: String,
    all_claims: Option<bool>,
    requested_claims: Option<Vec<String>>
}


struct ServerClient {
    application: String
}

impl ServerClient {
    fn prepare_login(user_id: &str, all_claims: Option<bool>, requested_claims: Option<Vec<String>>) -> ApplicationLogin {
        ApplicationLogin { user_id: user_id.to_owned(), all_claims, requested_claims }
    }
}

struct UserClient {
    application: String,
    client: reqwest::Client,
    base_url: Url,
    
}

impl UserClient {
    fn at(&self, path: &str) -> Url {
        self.base_url.join(path).unwrap()
    }

     async fn login_user(&self, app_login: ApplicationLogin, password: &str) -> Result<(), OneOf<(OpqError,)>> {
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

        Ok(())
    }
}