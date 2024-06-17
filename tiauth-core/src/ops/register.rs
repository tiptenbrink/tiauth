use opaque_borink::{server::register_server, Error as OpaqueError};

use crate::data::{pop_state, set_login_field, write_state, StateEntry, StateType};
use crate::error::WrapErrorOneOf;
use crate::state::State;
use crate::util::nonce_384;
use opaque_borink::server::register_server_finish;
use redb::Error;
use std::str;
use terrors::OneOf;

/// This function can be called by anyone, the server simply uses its private key to provide the material for the client to move to the next step.
/// While it uses the user_id given by the client (which should adhere to some limits), this is checked at a later stage.
/// It is important to rate-limit this, because the `register_server` function is not cheap to compute.
fn start_register(
    state: &mut State,
    application: &str,
    request: &str,
    user_id: &str,
) -> Result<(String, String), OneOf<(Error, OpaqueError)>> {
    let response = register_server(&state.private.opaque, request, user_id).to_one_of_twond()?;

    let entropy = nonce_384(state.rng);
    let entry = StateEntry::new(
        user_id,
        StateType::SetPassword,
        entropy,
        None,
        "".to_owned(),
    );
    let nonce = entry.key();

    write_state(state, application, entry).to_one_of_two()?;

    Ok((response, nonce))
}

fn register_finish(
    state: &mut State,
    application: &str,
    request: &str,
    register_flow_nonce: &str,
) -> Result<(), OneOf<(Error, OpaqueError)>> {
    let password_file = register_server_finish(request).to_one_of_twond()?;

    let entry = pop_state(
        state,
        application,
        register_flow_nonce,
        vec![StateType::SetPassword, StateType::ChangePassword],
    )
    .to_one_of_two()?;

    if let Some(entry) = entry {
        let require_unset_password = match entry.state_type {
            StateType::ChangePassword => false,
            StateType::SetPassword => true,
            _ => true,
        };

        set_login_field(
            state,
            application,
            &entry.user_id,
            password_file,
            require_unset_password,
        )
        .to_one_of_two()?;
    } else {
        panic!("Invalid nonce.")
    }

    Ok(())
}

pub mod test_util {
    use opaque_borink::client::{client_register, client_register_finish};
    use rmpv::Value;

    use crate::{
        data::{set_login, Login},
        state::State,
    };

    use super::*;

    pub fn create_user(
        state: &mut State,
        user_id: &str,
        application: &str,
        password: &str,
        claims: Option<Value>,
    ) {
        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims: claims.unwrap_or(Value::Map(Vec::new())),
        };

        set_login(state, &value, application).unwrap();

        let (request, client_state) = client_register(password).unwrap();
        let (server_response, nonce) =
            start_register(state, application, &request, user_id).unwrap();
        let request = client_register_finish(&client_state, password, &server_response).unwrap();
        register_finish(state, application, &request, &nonce).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        data::{get_login, Login},
        state::StateOwner,
    };

    use super::test_util::*;
    use super::*;

    use rmpv::Value;

    #[test]
    fn register() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let user_id = "hi";

        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims: Value::Map(Vec::new()),
        };
        let app = "abc";
        let password = "pass";

        create_user(&mut state, user_id, app, password, None);

        let read_login = get_login(&mut state, app, &value.user_id).unwrap();

        assert_ne!(value.password_file, read_login.password_file)
    }
}
