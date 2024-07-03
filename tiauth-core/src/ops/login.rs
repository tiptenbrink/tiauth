#![allow(dead_code)]

use crate::data::EXPIRE_TIME;
use crate::data::LEEWAY;
use crate::error::WrapErrorOneOf;
use crate::proof::create_session;
use crate::state::State;
use crate::store::{
    get_login, get_login_claims_bytes, pop_ephemeral, write_ephemeral, EphemeralEntry,
    EphemeralType,
};
use crate::util::nonce_384;
use crate::Session;
use opaque_borink::server::{login_server, login_server_finish};
use opaque_borink::Error as OpaqueError;
use redb::Error;
use std::borrow::Borrow;
use std::str;
use std::time::SystemTime;
use terrors::OneOf;

// TODO implement fake credential, also if password file is empty
pub fn login_start(
    state: &impl State,
    application: &str,
    user_id: &str,
    request: &str,
) -> Result<(String, String), OneOf<(Error, OpaqueError)>> {
    let read_login = get_login(state, application, user_id).unwrap().unwrap();

    let (response, state_data) = login_server(
        &state.private().opaque,
        &read_login.password_file,
        request,
        user_id,
    )
    .to_one_of_twond()?;

    let entropy = nonce_384(&mut state.rng());

    let entry = EphemeralEntry::new(user_id, EphemeralType::Opaque, entropy, None, state_data);
    let nonce = entry.key();

    write_ephemeral(state, application, entry).to_one_of_two()?;

    Ok((response, nonce))
}

/// This performs the final login step in the OPAQUE protocol. We retrieve the state using the nonce, which is the serialized state entry key, which includes an
/// expiry and the user_id, which ensures they are the same values as in the first step. The server generates a secret based on the client request and stored state.
/// If the secret is the same as the client's, we are certain that login succeeded.
pub fn login_finish(
    state: &impl State,
    application: &str,
    request: &str,
    nonce: &str,
) -> Result<(String, String), OneOf<(Error, OpaqueError)>> {
    let entry = pop_ephemeral(state, application, nonce, vec![EphemeralType::Opaque])
        .to_one_of_two()?
        .unwrap();

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now > entry.expires + LEEWAY {
        panic!("Login has expired!")
    }

    let secret = login_server_finish(request, &entry.value.unwrap()).to_one_of_twond()?;

    Ok((secret, entry.user_id))
}

fn login_session<S: AsRef<str>>(
    state: &impl State,
    application: &str,
    request: &str,
    nonce: &str,
    secret: &str,
    requested_claims: Option<Vec<S>>,
) -> Result<Session, OneOf<(Error, OpaqueError)>> {
    let (server_secret, user_id) = login_finish(state, application, request, nonce)?;

    if secret != server_secret {
        panic!("Secrets do not match, invalid login!")
    }

    let claims = get_login_claims_bytes(state, application, &user_id, requested_claims)
        .to_one_of_two()?
        .unwrap();

    let key = &state.private().session;

    let session = create_session(application, &user_id, EXPIRE_TIME, claims.borrow(), key);

    Ok(session)
}

#[cfg(feature = "test")]
pub mod test_util {
    use crate::{data::Claims, ops::register::test_util::*, state::test_util::TestState, Proof};
    use opaque_borink::client::{client_login, client_login_finish};

    use super::*;

    pub fn login_create_session(
        state: &TestState,
        user_id: &str,
        application: &str,
        password: &str,
        claims: Option<&Proof<Claims>>,
        // empty vec is no claims, none is all claims (default)
        session_claims: Option<Vec<&str>>,
    ) -> Session {
        register_flow(state, user_id, application, password, None, claims);

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(state, application, user_id, &request).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        login_session(
            state,
            application,
            &request,
            &nonce,
            &secret,
            session_claims,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::data::ByteSerial;
    use crate::ops::verify::test_util::*;
    use crate::verify::verify_session;
    use crate::{data::Claims, state::test_util::TestState};

    use crate::ops::register::test_util::*;
    use opaque_borink::client::{client_login, client_login_finish};

    #[test]
    fn login() {
        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        register_flow(&state, user_id, app, password, None, None);

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(&state, app, user_id, &request).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        let (secret_server, login_user_id) = login_finish(&state, app, &request, &nonce).unwrap();

        assert_eq!(secret, secret_server);
        assert_eq!(user_id, login_user_id);
    }

    #[test]
    fn test_login_session() {
        let email_value = "hi@abc.nl";
        let claims = Claims::new(vec![("email", email_value), ("other_claim", "other_value")]);

        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        let claims_proof = create_proof_claims(&state, app, user_id, None, claims.serialize());

        register_flow(&state, user_id, app, password, None, Some(&claims_proof));

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(&state, app, user_id, &request).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        let session =
            login_session(&state, app, &request, &nonce, &secret, Some(vec!["email"])).unwrap();

        let verified = verify_session(&state, &session).unwrap();

        let verified_read = verified.read().unwrap();

        let claims = verified_read.session_claims.deserialize();

        let claims_email = claims.get_claim("email");
        assert_eq!(email_value.as_bytes(), claims_email)
    }
}
