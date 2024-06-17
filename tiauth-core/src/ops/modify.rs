use crate::crypto::verify_signature;
use crate::data::{app_key, session_table, set_login_field_write, state_table, Session, StateEntry, StateType};
use crate::error::WrapErrorOneOf;
use crate::ops::prove::{proof_data, verify_proof_write};
use crate::state::State;
use crate::util::nonce_384;
use base64::{engine::general_purpose as b64, Engine as _};
use redb::{Error, ReadableTable};
use terrors::OneOf;
use std::time::SystemTime;

use super::prove::{verify_proof_meta, verify_session, InvalidProof, Proof, ProofUse, LEEWAY};

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
fn reset_password(state: &mut State, proof: Proof) -> Result<String, OneOf<(InvalidProof, Error)>> {
    verify_proof_meta(state, &proof)?;

    let change_nonce = if let ProofUse::ResetPassword(user_id) = &proof.proof_use {
        let entropy = nonce_384(&mut state.rng);
        let set_entry = StateEntry::new(&user_id, StateType::SetPassword, entropy, None, "".to_owned());
        let set_nonce = set_entry.key();

        let write_txn = state.db.begin_write().to_one_of_twond()?;
        {
            verify_proof_write(state, &write_txn, &proof)?;

            assert!(set_login_field_write(
                &write_txn,
                state,
                &proof.application,
                &user_id,
                "".to_owned(),
                false,
                false
            ).to_one_of_twond()?);

            let state_table_def = state_table(state.tables, &proof.application);
    
            let mut state_table = write_txn.open_table(state_table_def).to_one_of_twond()?;

            state_table.insert(set_entry.key().as_str(), set_entry.value.unwrap().as_str()).to_one_of_twond()?;
        }
        write_txn.commit().to_one_of_twond()?;

        set_nonce
    } else {
        // TODO make error
        panic!("Proof for reset password must be reset_password!")
    };

    Ok(change_nonce)
}

fn change_password(state: &mut State, raw_session: &[u8]) -> Result<String, Error> {
    let session = verify_session(state, raw_session).unwrap();
    
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > session.expires + LEEWAY {
        panic!("Session has expired!");
    }

    let entropy = nonce_384(&mut state.rng);
    let change_entry = StateEntry::new(&session.user_id, StateType::ChangePassword, entropy, None, "".to_owned());
    let change_nonce = change_entry.key();
    let session_table_def = session_table(&mut state.tables, &session.application);
    

    let write_txn = state.db.begin_write()?;
    {
        let table = write_txn.open_table(session_table_def)?;

        let state_table_def = state_table(&mut state.tables, &session.application);

        let result = table.get(raw_session)?;

        if result.is_some() {
            panic!("Session has been revoked!");
        }
        
        let mut state_table = write_txn.open_table(state_table_def)?;

        state_table.insert(change_entry.key().as_str(), change_entry.value.unwrap().as_str())?;
    }
    write_txn.commit()?;

    Ok(change_nonce)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::configure::test_util::*;
    use crate::data::get_login;
    use crate::ops::login::test_util::*;
    use crate::ops::prove::test_util::*;
    use crate::ops::register::test_util::*;
    use crate::state::StateOwner;
    use crate::util::msgpack_map;

    #[test]
    fn test_reset_password() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        //let claims = msgpack_map(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);

        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        create_user(&mut state, user_id, app, password, None);

        let key = create_register_app(&mut state, app).unwrap();

        let proof = create_proof(&mut state.rng, &key, app, None, ProofUse::ResetPassword(user_id.to_owned()));

        let nonce = reset_password(&mut state, proof).unwrap();

        let login = get_login(&mut state, app, user_id).unwrap();

        assert_eq!(login.password_file, "");


    }

    // #[test]
    // fn test_change_password() {
    //     let tmp = tempfile::NamedTempFile::new().unwrap();
    //     let mut state_owner = StateOwner::setup(tmp.path()).unwrap();
    //     let mut state = State::from_state_owner(&mut state_owner).unwrap();

    //     //let claims = msgpack_map(vec![("email", "hi@abc.nl"), ("other_claim", "other_value")]);

    //     let user_id = "hi";
    //     let app = "abc";
    //     let password = "pass";

    //     let session = login_create_session(
    //         &mut state,
    //         user_id,
    //         app,
    //         password,
    //         None,
    //         None,
    //     );

    //     let key = create_register_app(&mut state, app).unwrap();

    //     let proof = create_proof(&mut state.rng, &key, app, None, ProofUse::ResetPassword(user_id.to_owned()));

        
    // }
}