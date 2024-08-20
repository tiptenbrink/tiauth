#![allow(dead_code)]

use crate::data::SessionClaims;
use crate::data::COUNTER_EXPIRES;
use crate::data::EXPIRE_TIME;
use crate::error::OneOfTo;
use crate::proof::Ephemeral;
use crate::proof::EphemeralLoginState;
use crate::proof::EphemeralType;
use crate::proof::InvalidEphemeral;
use crate::proof::PasswordFileHash;
use crate::state::State;
use crate::store::users;
use crate::store::StoreError;
use crate::AppState;
use crate::ByteSerial;
use crate::KeyState;
use crate::Session;
use opaque_borink::server::{login_server, login_server_finish};
use opaque_borink::Error as OpaqueError;
use std::borrow::Borrow;
use std::str;
use terrors::OneOf;
use thiserror::Error;

// TODO implement fake credential, also if password file is empty
pub fn login_start(
    state: &impl State,
    request: &str,
    user_id: &str,
) -> Result<(String, Ephemeral<String>), OneOf<(StoreError, OpaqueError)>> {
    let read_login = users::get_login(state.store(), user_id)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    let read_login = if let Some(read_login) = read_login {
        read_login
    } else {
        todo!()
    };

    let (response, state_data) = login_server(
        state.keys().opaque(),
        &read_login.password_file,
        request,
        user_id,
    )
    .to_one_of()
    .map_err(OneOf::broaden)?;

    let time = state.time();

    let key = state.keys().ephemeral_key(time);

    let eph_type = EphemeralType::Login;
    let expires = time + COUNTER_EXPIRES;
    let state_input = EphemeralLoginState {
        expires,
        count: state.counter_next(user_id, expires),
        password_file: read_login.password_file,
    };
    let data = <String as ByteSerial>::serialize(&state_data);
    let eph = Ephemeral::create_expires(
        &key,
        user_id,
        state_input,
        eph_type,
        expires,
        data.as_packed(),
    );

    Ok((response, eph))
}

/// This performs the final login step in the OPAQUE protocol. We retrieve the state using the nonce, which is the serialized state entry key, which includes an
/// expiry and the user_id, which ensures they are the same values as in the first step. The server generates a secret based on the client request and stored state.
/// If the secret is the same as the client's, we are certain that login succeeded.
fn login_finish(
    state: &impl State,
    request: &str,
    nonce: &Ephemeral<String>,
) -> Result<(String, String, PasswordFileHash), OneOf<(OpaqueError, InvalidEphemeral, StoreError)>>
{
    let time = state.time();
    let verify_keys = state.keys().eph_veri_keys(time);
    let eph_decrypted = nonce
        .decrypt(&verify_keys)
        .to_one_of()
        .map_err(OneOf::broaden)?;
    let entry = eph_decrypted.read();

    let read_login = users::get_login(state.store(), entry.user_id)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    let read_login = if let Some(read_login) = read_login {
        read_login
    } else {
        todo!()
    };

    let new_pw_file_hash = PasswordFileHash::create(&read_login.password_file);

    let time = state.time();

    let opaque_state = entry
        .verify_state::<EphemeralLoginState, _>(time, |(count, expires, pw_file_hash)| {
            if state.counter_used(entry.user_id, count, expires, time)
                || new_pw_file_hash != pw_file_hash
            {
                return Err(InvalidEphemeral);
            }

            Ok(())
        })
        .to_one_of()
        .map_err(OneOf::broaden)?;

    // TODO check if OPAQUE login state can be revealed to the client
    let secret = login_server_finish(request, opaque_state)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    Ok((secret, entry.user_id.to_owned(), new_pw_file_hash))
}

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("User no longer exists!")]
    NotFound,
}

pub fn login_session(
    state: &impl State,
    request: &str,
    nonce: &Ephemeral<String>,
    secret: &str,
    requested_claims: SessionClaims,
) -> Result<Session, OneOf<(StoreError, OpaqueError, InvalidEphemeral, LoginError)>> {
    let (server_secret, user_id, pw_file_hash) =
        login_finish(state, request, nonce).map_err(OneOf::broaden)?;

    if secret != server_secret {
        panic!("Secrets do not match, invalid login!")
    }

    // TODO deal with missed claims
    let (claims, _missed_claims) =
        users::get_login_claims_bytes(state.store(), &user_id, &requested_claims)
            .to_one_of()
            .map_err(OneOf::broaden)?;

    let key = state.keys().session_key();

    let time = state.time();
    let session = Session::create(
        &user_id,
        EXPIRE_TIME,
        pw_file_hash,
        claims.borrow(),
        key,
        time,
    );

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
        password: &str,
        claims: Option<Claims>,
        // empty vec is no claims, none is all claims (default)
        session_claims: SessionClaims,
    ) -> Session {
        register_flow(state, user_id, password, None, claims);

        let (request, client_state) = client_login(password).unwrap();
        //let mut time_server = 0f64;
        //let before = Instant::now();
        let (response, nonce) = login_start(state, &request, user_id).unwrap();
        //time_server += Instant::now().duration_since(before).as_secs_f64()*1000f64;
        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();
        // println!("server time: {} ms", time_server);
        // let before = Instant::now();

        // time_server += Instant::now().duration_since(before).as_secs_f64()*1000f64;
        // println!("server time: {} ms", time_server);
        login_session(state, &request, &nonce, &secret, session_claims).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    //use crate::verify::verify_session;
    use crate::{data::Claims, state::test_util::TestState};

    use crate::ops::register::test_util::*;
    use opaque_borink::client::{client_login, client_login_finish};

    #[test]
    fn login() {
        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(app);

        register_flow(&state, user_id, password, None, None);

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(&state, &request, user_id).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        let (secret_server, login_user_id, _pw_file_hash) =
            login_finish(&state, &request, &nonce).unwrap();

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

        let state = TestState::setup_test(app);

        register_flow(&state, user_id, password, None, Some(claims));

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(&state, &request, user_id).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        let session = login_session(
            &state,
            &request,
            &nonce,
            &secret,
            SessionClaims::from_subset_str(vec!["email"]),
        )
        .unwrap();

        // let verified = verify_session(&state, &session).unwrap();

        // let verified_read = verified.read().unwrap();

        // let claims = verified_read.session_claims.deserialize();

        // let claims_email = claims.get_claim("email");
        // assert_eq!(email_value.as_bytes(), claims_email)
    }
}
