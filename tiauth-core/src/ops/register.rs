use opaque_borink::{server::register_server, Error as OpaqueError};

use crate::data::set_login_field;
use crate::error::WrapErrorOneOf;
use crate::state::State;
use opaque_borink::server::register_server_finish;
use redb::Error;
use std::str;
use terrors::OneOf;

fn start_register(state: &State, request: &str, user_id: &str) -> Result<String, OpaqueError> {
    register_server(&state.private.opaque, request, user_id)
}

fn register_finish(
    state: &mut State,
    application: &str,
    request: &str,
    user_id: &str,
    require_unset_password: bool,
) -> Result<(), OneOf<(Error, OpaqueError)>> {
    let password_file = register_server_finish(request).to_one_of_twond()?;

    set_login_field(
        state,
        application,
        user_id,
        password_file,
        require_unset_password,
    )
    .to_one_of_two()?;

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

    pub fn create_user(state: &mut State, user_id: &str, application: &str, password: &str) {
        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims: Value::Map(Vec::new()),
        };

        set_login(state, &value, application).unwrap();

        let (request, client_state) = client_register(password).unwrap();
        let server_response = start_register(state, &request, user_id).unwrap();
        let request = client_register_finish(&client_state, password, &server_response).unwrap();
        register_finish(state, application, &request, user_id, true).unwrap();
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
        let mut state_owner = StateOwner::setup().unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let user_id = "hi";

        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims: Value::Map(Vec::new()),
        };
        let app = "abc";
        let password = "pass";

        create_user(&mut state, user_id, app, password);

        let read_login = get_login(&mut state, app, &value.user_id).unwrap();

        assert_ne!(value.password_file, read_login.password_file)
    }
}
