use opaque_borink::{server::register_server, Error as OpaqueError};

use crate::crypto::VerifyFailed;
use crate::data::Claims;
use crate::data::InvalidProof;
use crate::encoded::Encodable;
use crate::error::{OneOfTo, WrapErrorOneOf};
use crate::proof::Ephemeral;
use crate::proof::EphemeralType;
use crate::proof::InvalidEphemeral;
use crate::state::State;
use crate::store::{login_change_ephemeral, SetLoginError};
use crate::{BytePacked, KeyState};
use opaque_borink::server::register_server_finish;
use redb::{Error as DbError, ReadableTable};
use std::str;
use terrors::OneOf;

/// This function can be called by anyone, the server simply uses its private key to provide the material for the client to move to the next step.
/// While it uses the user_id given by the client (which should adhere to some limits), this is checked at a later stage.
/// It is important to rate-limit this, because the `register_server` function is not cheap to compute.
pub fn start_register(
    state: &impl State,
    application: &str,
    request: &str,
    user_id: &str,
) -> Result<(String, Ephemeral<()>), OneOf<(DbError, OpaqueError)>> {
    let response = register_server(&state.private().opaque, request, user_id).to_one_of_twond()?;

    // let entropy = nonce_384(&mut state.rng());
    // let entry = EphemeralEntry::new(
    //     user_id,
    //     EphemeralType::NewUser,
    //     entropy,
    //     None,
    //     "".to_owned(),
    // );
    let key = state.keys().ephemeral_key(application);

    let ephemeral = Ephemeral::create(
        &key,
        user_id,
        application,
        &[],
        EphemeralType::NewUser,
        BytePacked::<()>::empty(),
    );

    Ok((response, ephemeral))
}

type FinishError = OneOf<(
    DbError,
    OpaqueError,
    InvalidProof,
    SetLoginError,
    InvalidEphemeral,
)>;

pub fn register_finish(
    state: &impl State,
    application: &str,
    request: &str,
    register_eph: &Ephemeral<()>,
) -> Result<(), FinishError> {
    let password_file = register_server_finish(request)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    let (verify_keys, _) = state.keys().eph_veri_keys(application);

    let content = register_eph.verify(&verify_keys, application)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    let write_txn = state
        .db()
        .begin_write()
        .into_one_of::<DbError>()
        .map_err(OneOf::broaden)?;

    {
        let mut table = write_txn
            .open_table(state.app_tables(application).users())
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;
        let new_login_bytes = if let Some(login_bytes) = table
            .get(content.user_id)
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?
        {
            login_change_ephemeral(&content, Some(login_bytes.value()), password_file)
                .map_err(OneOf::broaden)?
                .serialize()
        } else {
            login_change_ephemeral(&content, None, password_file)
                .map_err(OneOf::broaden)?
                .serialize()
        };

        table
            .insert(content.user_id, new_login_bytes.as_slice())
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;
    };

    write_txn
        .commit()
        .into_one_of::<DbError>()
        .map_err(OneOf::broaden)?;
    // // It can either be an entry from register_start (NewUser), or entry from reset_password (SetPassword), which cleared the password,
    // // or from change_password (ChangePassword)
    // else if let Some(entry) = pop_ephemeral(
    //     state,
    //     application,
    //     register_flow_nonce,
    //     vec![EphemeralType::SetPassword, EphemeralType::ChangePassword],
    // )
    // .to_one_of()
    // .map_err(OneOf::broaden)?
    // {
    //     let proof = if let Some(proof) = claims_proof {
    //         let key: crate::crypto::PublicKey = state.app_key(application);
    //         let proof_content =
    //             verify_proof_content(proof, &key, AboutVerify::new(application, ActionType::Set))
    //                 .map_err(OneOf::broaden)?;

    //         let user_id = proof_content.select_one().map_err(OneOf::broaden)?;
    //         if user_id != entry.user_id {
    //             return Err(OneOf::new(InvalidProof {}));
    //         }

    //         Some(proof_content)
    //     } else {
    //         None
    //     };

    //     let require_unset_password = match entry.eph_type {
    //         EphemeralType::ChangePassword => false,
    //         EphemeralType::SetPassword => true,
    //         _ => true,
    //     };

    //     let create_user = matches!(entry.eph_type, EphemeralType::NewUser);

    //     let write_txn = state
    //         .db()
    //         .begin_write()
    //         .into_one_of::<DbError>()
    //         .map_err(OneOf::broaden)?;

    //     let claims = if let Some(mut proof) = proof {
    //         verify_proof_write(state, &write_txn, &mut proof).map_err(OneOf::broaden)?;

    //         Some(proof.data)
    //     } else {
    //         None
    //     };

    //     match set_login_field_write(
    //         &write_txn,
    //         state,
    //         application,
    //         &entry.user_id,
    //         Some(password_file),
    //         claims,
    //         SetLoginOptions::new(require_unset_password, create_user),
    //     ) {
    //         Ok(()) => Ok(()),
    //         Err(e) => match entry.eph_type {
    //             EphemeralType::NewUser => match e.to_enum() {
    //                 terrors::E2::A(e) => Err(OneOf::new(e)),
    //                 // If it already exists, we do not want to cause an error to alert the user exists, it is up to the application to handle the rest of the defense against client enumeration
    //                 terrors::E2::B(LoginFieldError::AlreadyExists(_)) => Ok(()),
    //                 terrors::E2::B(e) => Err(OneOf::new(e)),
    //             },
    //             // For other types some additional check has been done that already implies the requester is trusted in some way (either through application proof or previous session)
    //             _ => Err(e.broaden()),
    //         },
    //     }?;

    //     write_txn
    //         .commit()
    //         .into_one_of::<DbError>()
    //         .map_err(OneOf::broaden)?;
    // } else {
    //     panic!("Invalid nonce.")
    // }

    Ok(())
}

#[cfg(feature = "test")]
pub mod test_util {
    use opaque_borink::client::{client_register, client_register_finish};

    use crate::{
        data::{Login, LoginPassword}, encoded::Encoded, state::test_util::TestState, store::{get_login, set_login}, ByteSerial
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
            start_register(state, application, &request, user_id).unwrap();
        let request = client_register_finish(&client_state, password, &server_response).unwrap();
        // Use alternative if provided
        let nonce = alt_eph.unwrap_or(nonce);

        register_finish(state, application, &request, &nonce).unwrap();

        if let Some(claims_set) = claims_set {
            let LoginPassword {
                user_id,
                password_file,
            } = get_login(state, application, user_id).unwrap().unwrap();

            let claims = claims_set.serialize();

            let claims_login = Login {
                user_id,
                password_file,
                claims: claims.as_packed(),
            };

            set_login(state, &claims_login, application).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        data::{ByteSerial, Claims, Login},
        state::test_util::TestState,
        store::get_login,
    };

    use super::test_util::*;

    #[test]
    fn register() {
        let user_id = "hi";
        let claims = Claims::empty().serialize();
        let claims = claims.as_packed();

        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims,
        };
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        register_flow(&state, user_id, app, password, None, None);

        let read_login = get_login(&state, app, &value.user_id).unwrap().unwrap();

        assert_ne!(value.password_file, read_login.password_file)
    }

    #[test]
    fn register_twice_noop() {
        let user_id = "hi";
        let claims = Claims::empty().serialize();
        let claims = claims.as_packed();

        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims,
        };
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        register_flow(&state, user_id, app, password, None, None);

        let read_login = get_login(&state, app, &value.user_id).unwrap().unwrap();
        let initial_pw_file = read_login.password_file;

        // Registering the second time should be a noop
        register_flow(&state, user_id, app, password, None, None);

        let read_login = get_login(&state, app, &value.user_id).unwrap().unwrap();

        assert_eq!(read_login.password_file, initial_pw_file)
    }
}
