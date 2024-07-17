#![allow(dead_code)]

use crate::data::Login;
use crate::data::SessionClaims;
use crate::data::EXPIRE_TIME;
use crate::data::LEEWAY;
use crate::error::OneOfTo;
use crate::error::WrapErrorOneOf;
use crate::proof::create_session;
use crate::proof::Ephemeral;
use crate::proof::EphemeralType;
use crate::proof::InvalidEphemeral;
use crate::state::State;
use crate::store::{
    get_login, get_login_claims_bytes
};
use crate::util::nonce_384;
use crate::util::nonce_384_bytes;
use crate::ByteOwned;
use crate::BytePacked;
use crate::ByteSerial;
use crate::KeyState;
use crate::Session;
use opaque_borink::server::{login_server, login_server_finish};
use opaque_borink::Error as OpaqueError;
use redb::Error as DbError;
use thiserror::Error;
use std::borrow::Borrow;
use std::str;
use std::time::SystemTime;
use terrors::OneOf;

// TODO implement fake credential, also if password file is empty
pub fn login_start(
    state: &impl State,
    application: &str,
    request: &str,
    user_id: &str,
) -> Result<(String, Ephemeral<String>), OneOf<(DbError, OpaqueError)>> {
    let read_login = get_login(state, application, user_id).unwrap().unwrap();

    let (response, state_data) = login_server(
        &state.private().opaque,
        &read_login.password_file,
        request,
        user_id,
    )
    .to_one_of_twond()?;
    let key = state.keys().ephemeral_key(application);

    let entropy = nonce_384_bytes(&mut state.rng());
    let data = <String as ByteSerial>::serialize(&state_data);
    let eph = Ephemeral::create(&key, user_id, application, &entropy, EphemeralType::Login, data.as_packed());

    Ok((response, eph))
}

/// This performs the final login step in the OPAQUE protocol. We retrieve the state using the nonce, which is the serialized state entry key, which includes an
/// expiry and the user_id, which ensures they are the same values as in the first step. The server generates a secret based on the client request and stored state.
/// If the secret is the same as the client's, we are certain that login succeeded.
fn login_finish<'a>(
    state: &'a impl State,
    application: &'a str,
    request: &'a str,
    nonce: &'a Ephemeral<String>,
) -> Result<(String, &'a str), OneOf<(DbError, OpaqueError, InvalidEphemeral)>> {
    let (verify_keys, _) = state.keys().eph_veri_keys(application);
    let entry = nonce.verify(&verify_keys, application).to_one_of().map_err(OneOf::broaden)?;

    let login_state = entry.data.try_deserialize().map_err(|_| OneOf::new(InvalidEphemeral))?;

    // let entry = pop_ephemeral(state, application, nonce, vec![EphemeralType::Opaque])
    //     .to_one_of_two()?
    //     .unwrap();

    // TODO check if OPAQUE login state can be revealed to the client
    let secret = login_server_finish(request, login_state).to_one_of().map_err(OneOf::broaden)?;

    

    Ok((secret, entry.user_id))
}

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("User no longer exists!")]
    NotFound
}

pub fn login_session(
    state: &impl State,
    application: &str,
    request: &str,
    nonce: &Ephemeral<String>,
    secret: &str,
    requested_claims: SessionClaims,
) -> Result<Session, OneOf<(DbError, OpaqueError, InvalidEphemeral, LoginError)>> {
    let (server_secret, user_id) = login_finish(state, application, request, nonce).map_err(OneOf::broaden)?;

    if secret != server_secret {
        panic!("Secrets do not match, invalid login!")
    }

    let claims = get_login_claims_bytes(state, application, &user_id, requested_claims)
        .to_one_of().map_err(OneOf::broaden)?.ok_or(OneOf::new(LoginError::NotFound))?;

    let key = &state.private().session;

    let session = create_session(application, &user_id, EXPIRE_TIME, claims.borrow(), key);

    Ok(session)
}

#[cfg(feature = "test")]
pub mod test_util {

    use crate::{data::Claims, ops::register::test_util::*, state::test_util::TestState};
    use opaque_borink::client::{client_login, client_login_finish};

    use super::*;

    pub fn login_create_session(
        state: &TestState,
        user_id: &str,
        application: &str,
        password: &str,
        claims: Option<Claims>,
        // empty vec is no claims, none is all claims (default)
        session_claims: SessionClaims,
    ) -> Session {
        register_flow(state, user_id, application, password, None, claims);

        let (request, client_state) = client_login(password).unwrap();
        //let mut time_server = 0f64;
        //let before = Instant::now();
        let (response, nonce) = login_start(state, application, &request, user_id).unwrap();
        //time_server += Instant::now().duration_since(before).as_secs_f64()*1000f64;
        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();
        // println!("server time: {} ms", time_server);
        // let before = Instant::now();

        // time_server += Instant::now().duration_since(before).as_secs_f64()*1000f64;
        // println!("server time: {} ms", time_server);
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

        let (response, nonce) = login_start(&state, app, &request, user_id).unwrap();

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

        register_flow(&state, user_id, app, password, None, Some(claims));

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(&state, app, &request, user_id).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        let session = login_session(
            &state,
            app,
            &request,
            &nonce,
            &secret,
            SessionClaims::from_subset_str(vec!["email"]),
        )
        .unwrap();

        let verified = verify_session(&state, &session).unwrap();

        let verified_read = verified.read().unwrap();

        let claims = verified_read.session_claims.deserialize();

        let claims_email = claims.get_claim("email");
        assert_eq!(email_value.as_bytes(), claims_email)
    }
}
