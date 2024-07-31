use opaque_borink::{server::register_server, Error as OpaqueError};
use thiserror::Error;

use crate::data::Claims;
use crate::data::InvalidProof;
use crate::data::UserPassword;
use crate::encoded::Encodable;
use crate::error::{OneOfTo, WrapErrorOneOf};
use crate::proof::Ephemeral;
use crate::proof::EphemeralChangePasswordState;
use crate::proof::EphemeralContent;
use crate::proof::EphemeralEmptyState;
use crate::proof::EphemeralStateType;
use crate::proof::EphemeralType;
use crate::proof::InvalidEphemeral;
use crate::state::State;
use crate::store::users;
use crate::store::ReadableTable;
use crate::store::StoreError;
use crate::AppState;
use crate::ByteSerial;
use crate::{BytePacked, KeyState};
use opaque_borink::server::register_server_finish;
use std::str;
use terrors::OneOf;

/// This function can be called by anyone, the server simply uses its private key to provide the material for the client to move to the next step.
/// While it uses the user_id given by the client (which should adhere to some limits), this is checked at a later stage.
/// It is important to rate-limit this, because the `register_server` function is not cheap to compute.
pub fn start_register(
    state: &impl State,
    request: &str,
    user_id: &str,
) -> Result<(String, Ephemeral<()>), OneOf<(OpaqueError,)>> {
    let response = register_server(state.keys().opaque(), request, user_id).to_one_of()?;
    let time = state.time();
    let key = state.keys().ephemeral_key(time);

    // For NewUser there is no real "state" to check against, it's just the state of there being no user
    let ephemeral = Ephemeral::create(
        &key,
        user_id,
        state.application(),
        EphemeralEmptyState,
        EphemeralType::NewUser,
        BytePacked::<()>::empty(),
    );

    Ok((response, ephemeral))
}

#[derive(Error, Debug)]
pub enum SetLoginError {
    #[error(
        "Could not set login as Ephemeral does not match expected state. Was it already used or did password change?"
    )]
    StateMismatch,
    // #[error("Could not set login with NewUser ephemeral: user already exists.")]
    // AlreadyExists,
    #[error("Could not set login: user does not exist.")]
    NotFound,
}

type FinishError = OneOf<(
    StoreError,
    OpaqueError,
    InvalidProof,
    SetLoginError,
    InvalidEphemeral,
)>;

fn user_change_ephemeral<T: ByteSerial>(
    entry: &EphemeralContent<T>,
    old_login_bytes: Option<&[u8]>,
    password_file: String,
) -> Result<UserPassword, OneOf<(SetLoginError, InvalidEphemeral,)>> {
    let login = match entry.eph_type {
        EphemeralType::NewUser => {
            // TODO check if we want AlreadyExists error
            if let Some(old_login_bytes) = old_login_bytes {
                return Ok(UserPassword::deserialize(old_login_bytes));
            }
            // if old_login_bytes.is_some() {
            //     return Err(OneOf::new(SetLoginError::AlreadyExists))
            // }
            // Note that the content is verified, so the state and data are not user-determined
            // It's a programming error if they are non-empty for the NewUser type
            entry.verify_state_equal::<EphemeralEmptyState>(EphemeralEmptyState).unwrap();

            UserPassword {
                user_id: entry.user_id.to_owned(),
                password_file,
            }
        }
        EphemeralType::ChangePassword => {
            let old_login_bytes = if let Some(old_login_bytes) = old_login_bytes {
                old_login_bytes
            } else {
                return Err(OneOf::new(SetLoginError::NotFound));
            };
            let login = UserPassword::deserialize(old_login_bytes);
            entry.verify_state_equal::<EphemeralChangePasswordState>(EphemeralChangePasswordState { password_file: login.password_file.to_owned() })
            .map_err(|_| OneOf::new(SetLoginError::StateMismatch))?;

            // Some programming error must have occurred if this happens
            assert_eq!(login.user_id, entry.user_id);

            UserPassword {
                user_id: entry.user_id.to_owned(),
                password_file,
            }
        },
        // Incorrect type
        _ => return Err(OneOf::new(InvalidEphemeral)),
    };

    Ok(login)
}

pub fn register_finish(
    state: &impl State,
    request: &str,
    register_eph: &Ephemeral<()>,
) -> Result<(), FinishError> {
    let password_file = register_server_finish(request)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    let time = state.time();
    let verify_keys = state.keys().eph_veri_keys(time);
    let eph_decrypted = register_eph.decrypt(&verify_keys)
        .to_one_of()
        .map_err(OneOf::broaden)?;
    let content = eph_decrypted.read();

    let store = state.store();
    let tx = store.open_write().to_one_of().map_err(OneOf::broaden)?;
    {
        let mut table = tx.user_table()
            .to_one_of().map_err(OneOf::broaden)?;


        let new_login_bytes = {
            let guarded_option = table.get(content.user_id)
                .to_one_of()
                .map_err(OneOf::broaden)?;
            // The `as_ref` here allows us to make this work
            let option_bytes = guarded_option.as_ref().map(|g| g.value());
            user_change_ephemeral(&content, option_bytes, password_file)
                .map_err(OneOf::broaden)?
                .serialize()
        };
        // if let Some(login_bytes) = table.get(content.user_id)
        //     .to_one_of()
        //     .map_err(OneOf::broaden)?
        // {
            
        // } else {
        //     user_change_ephemeral(&content, None, password_file)
        //         .map_err(OneOf::broaden)?
        //         .serialize()
        // };

        table
            .insert(content.user_id, new_login_bytes.as_slice())
            .to_one_of()
            .map_err(OneOf::broaden)?;
    };

    tx
        .commit()
        .to_one_of()
        .map_err(OneOf::broaden)?;

    Ok(())
}

#[cfg(feature = "test")]
pub mod test_util {
    use opaque_borink::client::{client_register, client_register_finish};

    use crate::{
        data::{UserClaims, UserPassword}, encoded::Encoded, state::test_util::TestState, store::users, ByteSerial
    };

    use super::*;

    pub fn register_flow(
        state: &TestState,
        user_id: &str,
        application: &str,
        password: &str,
        alt_eph: Option<Ephemeral<()>>,
        claims_set: Option<Claims>,
    ) {
        let (request, client_state) = client_register(password).unwrap();
        let (server_response, nonce) =
            start_register(state, &request, user_id).unwrap();
        let request = client_register_finish(&client_state, password, &server_response).unwrap();
        // Use alternative if provided
        let nonce = alt_eph.unwrap_or(nonce);

        register_finish(state, &request, &nonce).unwrap();

        if let Some(claims_set) = claims_set {
            let claims = claims_set.serialize();

            let claims_login = UserClaims {
                user_id: user_id.to_owned(),
                claims: claims.as_packed(),
            };

            users::set_login_claims(&state.store(), claims_login).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        data::{ByteSerial, Claims, UserPassword},
        state::test_util::TestState, store::users, AppState,
    };

    use super::test_util::*;

    #[test]
    fn register() {
        let user_id = "hi";
        //let claims = Claims::empty().serialize();
        //let claims = claims.as_packed();

        let value = UserPassword {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
        };
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(&app);

        register_flow(&state, user_id, app, password, None, None);

        let read_login = users::get_login(&state.store(), &value.user_id).unwrap().unwrap();

        assert_ne!(value.password_file, read_login.password_file)
    }

    #[test]
    fn register_twice_noop() {
        let user_id = "hi";
        //let claims = Claims::empty().serialize();
        //let claims = claims.as_packed();

        let value = UserPassword {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
        };
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(&app);

        register_flow(&state, user_id, app, password, None, None);

        let read_login = users::get_login(&state.store(), &value.user_id).unwrap().unwrap();
        let initial_pw_file = read_login.password_file;

        // Registering the second time should be a noop
        register_flow(&state, user_id, app, password, None, None);

        let read_login = users::get_login(&state.store(), &value.user_id).unwrap().unwrap();

        assert_eq!(read_login.password_file, initial_pw_file)
    }

    
}
