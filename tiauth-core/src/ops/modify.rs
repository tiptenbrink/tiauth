use crate::data::{
    set_login_field_write, LoginFieldError, SetLoginOptions, StateEntry, StateType, Tables,
};
use crate::error::OneOfTo;
use crate::ops::prove::verify_proof_write;
use crate::state::State;
use crate::util::nonce_384;
use redb::{Error as DbError, ReadableTable};
use std::time::SystemTime;
use terrors::OneOf;

use super::prove::{
    verify_proof_meta, verify_session, InvalidProof, Proof, ProofUseVerify, CHANGE_AGE, DELETE_AGE,
    LEEWAY,
};

/// Resets the password based on application proof. This is necessary because otherwise any user could reset another's password.
/// For example, an application could provide a proof to the client after a user presses a button in a reset password email.
/// A proof is simply a one-time signature of a statement that a specific user can reset their password. A proof is sensitive,
/// if it is leaked, it would allow an attacker to change the user's password to their liking! The public key that the server uses
/// to check the proof must be provided in advance (see `register_application`).
///
/// If a proof is used, the unique proof nonce is stored in the database so it cannot be used again. The proof also has an expiry
/// time (in seconds after the Unix epoch) and is no longer valid afterwards.
///
/// The function returns a "change nonce" that serves as a one-time token that allows one to re-enter the registration flow.
fn reset_password(
    state: &impl State,
    proof: Proof,
) -> Result<String, OneOf<(DbError, InvalidProof, LoginFieldError)>> {
    let (proof_info, proof_use) =
        verify_proof_meta(state, proof, ProofUseVerify::ResetPassword).map_err(OneOf::broaden)?;

    let user_id = proof_use.unwrap_user_id();

    let entropy = nonce_384(&mut state.rng());
    let set_entry = StateEntry::new(
        user_id,
        StateType::SetPassword,
        entropy,
        None,
        "".to_owned(),
    );
    let set_nonce = set_entry.key();

    let tables = state.tables().app(&proof_info.application);

    let write_txn = state
        .db()
        .begin_write()
        .into_one_of::<DbError>()
        .map_err(OneOf::broaden)?;
    {
        verify_proof_write(state, &write_txn, &proof_info).map_err(OneOf::broaden)?;

        set_login_field_write(
            &write_txn,
            state,
            &proof_info.application,
            user_id,
            Some("".to_owned()),
            None,
            SetLoginOptions::new(false, false),
        )
        .map_err(OneOf::broaden)?;

        let mut state_table = write_txn
            .open_table(tables.state())
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;

        state_table
            .insert(set_entry.key().as_str(), set_entry.value.unwrap().as_str())
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;
    }
    write_txn
        .commit()
        .into_one_of::<DbError>()
        .map_err(OneOf::broaden)?;

    Ok(set_nonce)
}

fn change_password(state: &impl State, raw_session: &[u8]) -> Result<String, OneOf<(DbError,)>> {
    let session = verify_session(state, raw_session).unwrap();

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > session.expires + LEEWAY {
        panic!("Session has expired!");
    }

    if time > session.issued + CHANGE_AGE {
        panic!("Session too old to be used for changing password!");
    }

    let entropy = nonce_384(&mut state.rng());
    let change_entry = StateEntry::new(
        &session.user_id,
        StateType::ChangePassword,
        entropy,
        None,
        "".to_owned(),
    );
    let change_nonce = change_entry.key();
    let tables = state.tables().app(&session.application);

    let write_txn = state.db().begin_write().into_one_of()?;
    {
        let table = write_txn.open_table(tables.sessions()).into_one_of()?;

        let result = table.get(raw_session).into_one_of()?;

        if result.is_some() {
            panic!("Session has been revoked!");
        }

        let mut state_table = write_txn.open_table(tables.state()).into_one_of()?;

        state_table
            .insert(
                change_entry.key().as_str(),
                change_entry.value.unwrap().as_str(),
            )
            .into_one_of()?;
    }
    write_txn.commit().into_one_of()?;

    Ok(change_nonce)
}

fn session_delete_user(state: &impl State, raw_session: &[u8]) -> Result<(), OneOf<(DbError,)>> {
    let session = verify_session(state, raw_session).unwrap();

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > session.expires + LEEWAY {
        panic!("Session has expired!");
    }

    if time > session.issued + DELETE_AGE {
        panic!("Session too old to be used for deleting account!");
    }

    let tables = state.tables().app(&session.application);

    let write_txn = state
        .db()
        .begin_write()
        .into_one_of::<DbError>()
        .map_err(OneOf::broaden)?;
    {
        let table = write_txn
            .open_table(tables.sessions())
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;

        let result = table
            .get(raw_session)
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;

        if result.is_some() {
            panic!("Session has been revoked!");
        }

        let mut table = write_txn
            .open_table(tables.users())
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;

        table
            .remove(session.user_id.as_str())
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;
    }
    write_txn
        .commit()
        .into_one_of::<DbError>()
        .map_err(OneOf::broaden)?;

    Ok(())
}

fn app_delete_user(state: &impl State, proof: Proof) -> Result<(), OneOf<(DbError, InvalidProof)>> {
    let (proof_info, proof_use) =
        verify_proof_meta(state, proof, ProofUseVerify::DeleteUser).map_err(OneOf::broaden)?;

    let tables = state.tables().app(&proof_info.application);

    let write_txn = state
        .db()
        .begin_write()
        .into_one_of::<DbError>()
        .map_err(OneOf::broaden)?;
    {
        verify_proof_write(state, &write_txn, &proof_info).map_err(OneOf::broaden)?;

        let mut table = write_txn
            .open_table(tables.users())
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;

        table
            .remove(proof_use.unwrap_user_id())
            .into_one_of::<DbError>()
            .map_err(OneOf::broaden)?;
    }
    write_txn
        .commit()
        .into_one_of::<DbError>()
        .map_err(OneOf::broaden)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::get_login;
    use crate::ops::login::test_util::*;
    use crate::ops::prove::{test_util::*, ProofUse};
    use crate::ops::register::test_util::*;
    use crate::state::test_util::TestState;

    #[test]
    fn test_reset_password() {
        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        register_flow(&state, user_id, app, password, None, None);

        let proof = Proof::create(
            &mut state.rng(),
            state.proof_key(app),
            app,
            None,
            ProofUse::ResetPassword {
                user_id: user_id.to_owned(),
            },
        );

        let nonce = reset_password(&state, proof).unwrap();

        let login = get_login(&state, app, user_id).unwrap().unwrap();

        assert_eq!(login.password_file, "");

        register_flow(&state, user_id, app, password, Some(&nonce), None);

        let login = get_login(&state, app, user_id).unwrap().unwrap();

        assert!(!login.password_file.is_empty());
    }

    #[test]
    fn test_change_password() {
        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        let session = login_create_session(&state, user_id, app, password, None, None);

        let nonce = change_password(&state, &session).unwrap();

        let login = get_login(&state, app, user_id).unwrap().unwrap();
        let initial_pw_file = login.password_file;

        assert_ne!(initial_pw_file, "");

        register_flow(&state, user_id, app, password, Some(&nonce), None);

        let login = get_login(&state, app, user_id).unwrap().unwrap();

        assert_ne!(initial_pw_file, login.password_file);
    }

    #[test]
    fn test_delete_passsword() {
        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        let session = login_create_session(&state, user_id, app, password, None, None);

        session_delete_user(&state, &session).unwrap();

        let login = get_login(&state, app, user_id).unwrap();

        assert!(login.is_none());
    }

    #[test]
    fn test_delete_passsword_app() {
        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        register_flow(&state, user_id, app, password, None, None);

        let proof = Proof::create(
            &mut state.rng(),
            state.proof_key(app),
            app,
            None,
            ProofUse::DeleteUser {
                user_id: user_id.to_owned(),
            },
        );

        app_delete_user(&state, proof).unwrap();

        let login = get_login(&state, app, user_id).unwrap();

        assert!(login.is_none());
    }
}
