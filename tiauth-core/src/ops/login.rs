#![allow(dead_code)]

use crate::crypto::{self};
use crate::data::{get_login, read_state, write_state, Session};
use crate::error::WrapErrorOneOf;
use crate::state::State;
use crate::util::nonce_384;
use opaque_borink::server::{login_server, login_server_finish};
use opaque_borink::Error as OpaqueError;
use redb::Error;
use rmp_serde::encode;
use rmpv::Value;
use std::collections::HashSet;
use std::str;
use std::time::SystemTime;
use terrors::OneOf;

// TODO implement fake credential, also if password file is empty
fn login_start(
    state: &mut State,
    application: &str,
    user_id: &str,
    request: &str,
) -> Result<(String, String), OneOf<(Error, OpaqueError)>> {
    let read_login = get_login(state, application, user_id).unwrap();

    let (response, state_data) = login_server(
        &state.private.opaque,
        &read_login.password_file,
        request,
        user_id,
    )
    .to_one_of_twond()?;

    let nonce = nonce_384(state.rng);
    let key = format!("{}:{}", user_id, nonce);

    write_state(state, application, &key, &state_data).to_one_of_two()?;

    Ok((response, nonce))
}

/// This performs the final login step in the OPAQUE protocol. We retrieve the state using the nonce and provided user_id, making it bound to these and ensuring
/// they are the same values as in the first step. The server generates a secret based on the client request and stored state. If the secret is the same as the
/// client's, we are certain that login succeeded.
fn login_finish(
    state: &mut State,
    application: &str,
    user_id: &str,
    request: &str,
    nonce: &str,
) -> Result<String, OneOf<(Error, OpaqueError)>> {
    // 384 bits nonce, i.e. 48 bytes, 64 base64url characters, which are all 1 byte, so 64 bytes
    assert_eq!(nonce.len(), 64);

    let key = format!("{}:{}", user_id, nonce);

    let state = read_state(state, application, &key).to_one_of_two()?;

    let secret = login_server_finish(request, &state).to_one_of_twond()?;

    Ok(secret)
}

// 1 month
const EXPIRE_TIME: u64 = 30 * 24 * 60 * 60;

fn login_session(
    state: &mut State,
    application: &str,
    user_id: &str,
    request: &str,
    nonce: &str,
    secret: &str,
    requested_claims: Vec<String>,
) -> Result<Vec<u8>, OneOf<(Error, OpaqueError)>> {
    let server_secret = login_finish(state, application, user_id, request, nonce)?;

    if secret != server_secret {
        panic!("Secrets do not match, invalid login!")
    }

    let claims = get_login(state, application, user_id)
        .to_one_of_two()?
        .claims;

    let mut requested_claims: HashSet<String> = HashSet::from_iter(requested_claims);

    let session_claims: Vec<(Value, Value)> = if let Value::Map(entries) = claims {
        entries
            .into_iter()
            .filter(|(key, _value)| {
                if let Value::String(key) = key {
                    if key.is_err() {
                        panic!("Keys must be valid UTF-8!")
                    }

                    let key = key.as_str().unwrap();

                    requested_claims.remove(key)
                } else {
                    panic!("All claims must be string keys!")
                }
            })
            .collect()
    } else {
        panic!("Claims must be a map type!");
    };

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session = Session {
        user_id: user_id.to_owned(),
        expires: time + EXPIRE_TIME,
        session_claims: Value::Map(session_claims),
    };

    let session_encoded = encode::to_vec_named(&session).unwrap();

    Ok(crypto::session(
        &session_encoded,
        &state.private.session,
        state.rng,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ops::register::test_util::*;
    use crate::state::StateOwner;
    use opaque_borink::client::{client_login, client_login_finish};

    #[test]
    fn login() {
        let mut state_owner = StateOwner::setup().unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        create_user(&mut state, user_id, app, password);

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(&mut state, app, user_id, &request).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        let secret_server = login_finish(&mut state, app, user_id, &request, &nonce).unwrap();

        assert_eq!(secret, secret_server)
    }
}
