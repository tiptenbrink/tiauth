#![allow(dead_code)]

use crate::crypto::{self};
use crate::data::{get_login, pop_state, write_state, Session, StateEntry, StateType};
use crate::error::WrapErrorOneOf;
use crate::ops::prove::LEEWAY;
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

    let entropy = nonce_384(state.rng);

    let entry = StateEntry::new(user_id, StateType::Opaque, entropy, None, state_data);
    let nonce = entry.key();

    write_state(state, application, entry).to_one_of_two()?;

    Ok((response, nonce))
}

/// This performs the final login step in the OPAQUE protocol. We retrieve the state using the nonce, which is the serialized state entry key, which includes an
/// expiry and the user_id, which ensures they are the same values as in the first step. The server generates a secret based on the client request and stored state.
/// If the secret is the same as the client's, we are certain that login succeeded.
fn login_finish(
    state: &mut State,
    application: &str,
    request: &str,
    nonce: &str,
) -> Result<(String, String), OneOf<(Error, OpaqueError)>> {
    let entry = pop_state(state, application, nonce, vec![StateType::Opaque])
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

// 1 month
const EXPIRE_TIME: u64 = 30 * 24 * 60 * 60;

fn login_session<S: AsRef<str>>(
    state: &mut State,
    application: &str,
    request: &str,
    nonce: &str,
    secret: &str,
    requested_claims: Vec<S>,
) -> Result<Vec<u8>, OneOf<(Error, OpaqueError)>> {
    let (server_secret, user_id) = login_finish(state, application, request, nonce)?;

    if secret != server_secret {
        panic!("Secrets do not match, invalid login!")
    }

    let claims = get_login(state, application, &user_id)
        .to_one_of_two()?
        .claims;

    let mut requested_claims: HashSet<&str> =
        HashSet::from_iter(requested_claims.iter().map(|s| s.as_ref()));

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
        application: application.to_owned(),
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

pub mod test_util {
    use crate::ops::register::test_util::*;
    use opaque_borink::client::{client_login, client_login_finish};
    use rmpv::Value;

    use super::*;

    pub fn login_create_session(
        state: &mut State,
        user_id: &str,
        application: &str,
        password: &str,
        claims: Option<Value>,
        session_claims: Option<Vec<&str>>,
    ) -> Vec<u8> {
        create_user(state, user_id, application, password, claims);

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(state, application, user_id, &request).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        login_session(
            state,
            application,
            &request,
            &nonce,
            &secret,
            session_claims.unwrap_or_default(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::state::StateOwner;
    use crate::{ops::register::test_util::*, util::msgpack_map};
    use opaque_borink::client::{client_login, client_login_finish};

    #[test]
    fn login() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        create_user(&mut state, user_id, app, password, None);

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(&mut state, app, user_id, &request).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        let (secret_server, login_user_id) =
            login_finish(&mut state, app, &request, &nonce).unwrap();

        assert_eq!(secret, secret_server);
        assert_eq!(user_id, login_user_id);
    }

    #[test]
    fn test_login_session() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let claims = msgpack_map(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);

        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        create_user(&mut state, user_id, app, password, Some(claims));

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(&mut state, app, user_id, &request).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        let session =
            login_session(&mut state, app, &request, &nonce, &secret, vec!["email"]).unwrap();

        assert!(!session.is_empty());
    }
}
