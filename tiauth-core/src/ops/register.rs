use opaque_borink::{server::register_server, Error as OpaqueError};

use crate::data::{
    pop_state, set_login_field_write, write_state, LoginFieldError, SetLoginOptions, StateEntry,
    StateType,
};
use crate::error::{OneOfTo, WrapErrorOneOf};
use crate::ops::prove::verify_proof_write;
use crate::state::State;
use crate::util::nonce_384;
use opaque_borink::server::register_server_finish;
use redb::Error as DbError;
use std::str;
use terrors::OneOf;

use super::prove::{verify_proof_meta, InvalidProof, Proof, ProofUseVerify};

/// This function can be called by anyone, the server simply uses its private key to provide the material for the client to move to the next step.
/// While it uses the user_id given by the client (which should adhere to some limits), this is checked at a later stage.
/// It is important to rate-limit this, because the `register_server` function is not cheap to compute.
fn start_register(
    state: &mut State,
    application: &str,
    request: &str,
    user_id: &str,
) -> Result<(String, String), OneOf<(DbError, OpaqueError)>> {
    let response = register_server(&state.private.opaque, request, user_id).to_one_of_twond()?;

    let entropy = nonce_384(state.rng);
    let entry = StateEntry::new(user_id, StateType::NewUser, entropy, None, "".to_owned());
    let nonce = entry.key();

    write_state(state, application, entry).to_one_of_two()?;

    Ok((response, nonce))
}

/// The proof should be for SetClaims. This should be verified beforehand.
fn register_finish(
    state: &mut State,
    application: &str,
    request: &str,
    register_flow_nonce: &str,
    claims_proof: Option<Proof>,
) -> Result<(), OneOf<(DbError, OpaqueError, InvalidProof, LoginFieldError)>> {
    let password_file = register_server_finish(request)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    let entry = pop_state(
        state,
        application,
        register_flow_nonce,
        vec![
            StateType::SetPassword,
            StateType::ChangePassword,
            StateType::NewUser,
        ],
    )
    .to_one_of()
    .map_err(OneOf::broaden)?;

    if let Some(entry) = entry {
        let proof = if let Some(proof) = claims_proof {
            let (proof_info, proof_use) =
                verify_proof_meta(state, proof, ProofUseVerify::SetClaims)
                    .map_err(OneOf::broaden)?;

            // The requested application/user_id must match the proof
            if proof_info.application != application || proof_use.unwrap_user_id() != entry.user_id
            {
                return Err(OneOf::new(InvalidProof {}));
            }

            Some((proof_info, proof_use))
        } else {
            None
        };

        let require_unset_password = match entry.state_type {
            StateType::ChangePassword => false,
            StateType::SetPassword => true,
            _ => true,
        };

        let create_user = matches!(entry.state_type, StateType::NewUser);

        let write_txn = state
            .db
            .begin_write()
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;

        let claims = if let Some((proof_info, proof_use)) = proof {
            verify_proof_write(state, &write_txn, &proof_info).map_err(OneOf::broaden)?;

            Some(proof_use.unwrap_claims())
        } else {
            None
        };

        match set_login_field_write(
            &write_txn,
            state,
            application,
            &entry.user_id,
            Some(password_file),
            claims,
            SetLoginOptions::new(require_unset_password, create_user),
        ) {
            Ok(()) => Ok(()),
            Err(e) => match entry.state_type {
                StateType::NewUser => match e.to_enum() {
                    terrors::E2::A(e) => Err(OneOf::new(e)),
                    // If it already exists, we do not want to cause an error to alert the user exists, it is up to the application to handle the rest of the defense against client enumeration
                    terrors::E2::B(LoginFieldError::AlreadyExists(_)) => Ok(()),
                    terrors::E2::B(e) => Err(OneOf::new(e)),
                },
                // For other types some additional check has been done that already implies the requester is trusted in some way (either through application proof or previous session)
                _ => Err(e.broaden()),
            },
        }?;

        write_txn
            .commit()
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;
    } else {
        panic!("Invalid nonce.")
    }

    Ok(())
}

pub mod test_util {
    use opaque_borink::client::{client_register, client_register_finish};

    use crate::state::State;

    use super::*;

    pub fn register_flow(
        state: &mut State,
        user_id: &str,
        application: &str,
        password: &str,
        alt_nonce: Option<&str>,
        claims_proof: Option<Proof>,
    ) {
        let (request, client_state) = client_register(password).unwrap();
        let (server_response, nonce) =
            start_register(state, application, &request, user_id).unwrap();
        let request = client_register_finish(&client_state, password, &server_response).unwrap();

        // Use alternative if provided
        let nonce = alt_nonce.unwrap_or(&nonce);

        register_finish(state, application, &request, nonce, claims_proof).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        data::{get_login, Claims, Login},
        state::StateOwner,
    };

    use super::test_util::*;
    use super::*;

    #[test]
    fn register() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let user_id = "hi";

        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims: Claims::default(),
        };
        let app = "abc";
        let password = "pass";

        register_flow(&mut state, user_id, app, password, None, None);

        let read_login = get_login(&mut state, app, &value.user_id).unwrap().unwrap();

        assert_ne!(value.password_file, read_login.password_file)
    }

    #[test]
    fn register_twice_noop() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let user_id = "hi";

        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims: Claims::default(),
        };
        let app = "abc";
        let password = "pass";

        register_flow(&mut state, user_id, app, password, None, None);

        let read_login = get_login(&mut state, app, &value.user_id).unwrap().unwrap();
        let initial_pw_file = read_login.password_file;

        // Registering the second time should be a noop
        register_flow(&mut state, user_id, app, password, None, None);

        let read_login = get_login(&mut state, app, &value.user_id).unwrap().unwrap();

        assert_eq!(read_login.password_file, initial_pw_file)
    }
}
