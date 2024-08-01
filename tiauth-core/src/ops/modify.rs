use crate::data::{
    ClaimKeys, ModifyClaimError, UserPassword, CHANGE_AGE, DELETE_AGE, LEEWAY
};
use crate::encoded::{Encodable, Encoded};
use crate::error::OneOfTo;
// use crate::ops::verify::verify_proof_write;
use crate::proof::{Ephemeral, EphemeralChangePasswordState, EphemeralType, InvalidProof, InvalidSession, ProofSingleTarget};
use crate::state::State;
use crate::store::{users, LoginFieldError, StoreError};
// use crate::verify::verify_session;
use crate::{ActionType, BytePacked, ByteSerial, Claims, KeyState, Proof, Session};
use std::time::SystemTime;
use terrors::OneOf;

use super::verify::{decrypt_session, verify_proof, verify_session};

// use super::verify::{verify_proof};

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
pub fn reset_password(
    state: &impl State,
    proof: &Proof<()>,
) -> Result<Ephemeral<()>, OneOf<(StoreError, InvalidProof, LoginFieldError)>> {
    let time = state.time();

    let proof_unvalidated = verify_proof(state, proof, time)
        .map_err(OneOf::broaden)?;
    
    let (_, user_id) = proof_unvalidated.validate(ActionType::ResetPassword, ProofSingleTarget).to_one_of().map_err(OneOf::broaden)?;

    let UserPassword { password_file, user_id } = match users::get_login(state.store(), &user_id)
        .to_one_of()
        .map_err(OneOf::broaden)?
    {
        Some(user) => user,
        None => {
            println!("User no longer exists!");
            return Err(OneOf::new(InvalidProof {}));
        }
    };
    // We check time again because we did a (potentially blocking) database access before.
    let time = state.time();
    
    let key = state.keys().ephemeral_key(time);

    // let entropy = nonce_384(&mut state.rng());
    // let set_entry = EphemeralEntry::new(
    //     &user_id,
    //     EphemeralType::SetPassword,
    //     entropy,
    //     None,
    //     "".to_owned(),
    // );
    // // TODO come up with eph bytes
    // let eph_bytes: Vec<u8> = Vec::new();
    // let set_nonce = set_entry.key();

    // let tables = state.app_tables(application);

    // let write_txn = state
    //     .db()
    //     .begin_write()
    //     .into_one_of::<DbError>()
    //     .map_err(OneOf::broaden)?;
    // {
    //     verify_proof_write(state, &write_txn, &mut proof_content).map_err(OneOf::broaden)?;

    //     set_login_field_write(
    //         &write_txn,
    //         state,
    //         application,
    //         &user_id,
    //         Some("".to_owned()),
    //         None::<ByteOwned<Claims>>,
    //         SetLoginOptions::new(false, false),
    //     )
    //     .map_err(OneOf::broaden)?;

    //     let mut eph_table = write_txn
    //         .open_table(tables.ephemeral())
    //         .into_one_of::<DbError>()
    //         .map_err(OneOf::broaden)?;

    //     eph_table
    //         .insert(set_entry.key().as_str(), set_entry.value.unwrap().as_str())
    //         .into_one_of::<DbError>()
    //         .map_err(OneOf::broaden)?;
    // }
    // write_txn
    //     .commit()
    //     .into_one_of::<DbError>()
    //     .map_err(OneOf::broaden)?;

    let state = EphemeralChangePasswordState { password_file };
    let change_entry = Ephemeral::create(
        &key,
        &user_id,
        state,
        EphemeralType::ChangePassword,
        time,
        BytePacked::<()>::empty(),
    );

    Ok(change_entry)
}

fn change_password(
    state: &impl State,
    session_encrypted: &Session,
) -> Result<Ephemeral<()>, OneOf<(StoreError, InvalidSession)>> {
    let time = state.time();
    let decrypted = decrypt_session(state, session_encrypted, time)
        .map_err(OneOf::broaden)?;
    let session = decrypted.read();

    let (_, password_file) = verify_session(state, &session, time, Some(CHANGE_AGE))?;

    let key = state.keys().ephemeral_key(time);

    let time = state.time();

    let state = EphemeralChangePasswordState { password_file };
    let change_entry = Ephemeral::create::<EphemeralChangePasswordState>(
        &key,
        &session.user_id,
        state,
        EphemeralType::ChangePassword,
        time,
        BytePacked::<()>::empty(),
    );

    Ok(change_entry)
}

// fn session_delete_user(
//     state: &impl State,
//     session_encrypted: &Session,
// ) -> Result<(), OneOf<(DbError,)>> {
//     let verified = verify_session(state, session_encrypted).unwrap();
//     let session = verified.read().unwrap();

//     let time = state.time();

//     if time > session.expires + LEEWAY {
//         panic!("Session has expired!");
//     }

//     if time > session.issued + DELETE_AGE {
//         panic!("Session too old to be used for deleting account!");
//     }

//     let tables = state.app_tables(&session.application);

//     let write_txn = state
//         .db()
//         .begin_write()
//         .into_one_of::<DbError>()
//         .map_err(OneOf::broaden)?;
//     {
//         let table = write_txn
//             .open_table(tables.sessions())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;

//         let result = table
//             .get(session_encrypted.raw_bytes())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;

//         if result.is_some() {
//             panic!("Session has been revoked!");
//         }

//         let mut table = write_txn
//             .open_table(tables.users())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;

//         table
//             .remove(session.user_id.as_str())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;
//     }
//     write_txn
//         .commit()
//         .into_one_of::<DbError>()
//         .map_err(OneOf::broaden)?;

//     Ok(())
// }

// fn app_delete_user(
//     state: &impl State,
//     application: &str,
//     proof: &Proof<()>,
// ) -> Result<(), OneOf<(DbError, InvalidProof)>> {
//     let key = state.app_key(application);
//     let mut proof_content: ProofContent<()> = verify_proof_content(
//         proof,
//         &key,
//         AboutVerify::new(application, ActionType::DeleteUser),
//     )
//     .map_err(OneOf::broaden)?;

//     let tables = state.app_tables(application);

//     let user_id = proof_content.select_one().map_err(OneOf::broaden)?;

//     let write_txn = state
//         .db()
//         .begin_write()
//         .into_one_of::<DbError>()
//         .map_err(OneOf::broaden)?;
//     {
//         verify_proof_write(state, &write_txn, &mut proof_content).map_err(OneOf::broaden)?;

//         let mut table = write_txn
//             .open_table(tables.users())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;

//         table
//             .remove(user_id.as_str())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;
//     }
//     write_txn
//         .commit()
//         .into_one_of::<DbError>()
//         .map_err(OneOf::broaden)?;

//     Ok(())
// }

// pub fn user_new_claims(
//     state: &impl State,
//     application: &str,
//     claims_proof: &Proof<Claims>,
// ) -> Result<(), OneOf<(InvalidProof, DbError, ModifyClaimError)>> {
//     let key = state.app_key(application);
//     let proof_content = verify_proof_content(
//         claims_proof,
//         &key,
//         AboutVerify::with_allowed(
//             application,
//             vec![
//                 ActionType::MergeClaims,
//                 ActionType::AddClaims,
//                 ActionType::SetClaims,
//             ],
//         ),
//     )
//     .map_err(OneOf::broaden)?;

//     let user_id = proof_content.select_one().map_err(OneOf::broaden)?;

//     let write_txn = state
//         .db()
//         .begin_write()
//         .into_one_of::<DbError>()
//         .map_err(OneOf::broaden)?;

//     {
//         let mut table = write_txn
//             .open_table(state.app_tables(application).users())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;

//         let new_login_bytes = {
//             let login = table
//                 .get(user_id.as_str())
//                 .into_one_of::<DbError>()
//                 .map_err(OneOf::broaden)?;

//             if let Some(login_bytes) = login {
//                 let login_bytes = login_bytes.value();
//                 let (login_password, claims) = Login::deserialize_tuple(login_bytes);

//                 let proof_claims = proof_content
//                     .data
//                     .try_deserialize()
//                     .map_err(|_| OneOf::new(InvalidProof {}))?;

//                 let new_claims = if proof_content.about.action == ActionType::SetClaims {
//                     proof_claims
//                         .to_claims_sorted()
//                         .map_err(|_| OneOf::new(ModifyClaimError::NotSorted))?
//                 } else {
//                     let claims = claims.deserialize();
//                     let exists_ok = if proof_content.about.action == ActionType::AddClaims {
//                         false
//                     } else if proof_content.about.action == ActionType::MergeClaims {
//                         true
//                     } else {
//                         panic!("Only action merge and add allowed!")
//                     };

//                     claims
//                         .add_claims(proof_claims, exists_ok)
//                         .to_one_of()
//                         .map_err(OneOf::broaden)?
//                 };

//                 login_password
//                     .into_login(new_claims.serialize().as_packed())
//                     .serialize()
//             } else {
//                 return Err(OneOf::new(ModifyClaimError::UserNotFound));
//             }
//         };

//         table
//             .insert(user_id.as_str(), new_login_bytes.as_slice())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;
//     }

//     Ok(())
// }

#[allow(unused_variables)]
pub fn user_remove_claims(
    state: &impl State,
    application: &str,
    claims_proof: &Proof<ClaimKeys>,
) -> Result<(), OneOf<(InvalidProof, StoreError, ModifyClaimError)>> {
    // let key = state.app_key(application);
    // let proof_content = verify_proof_content(
    //     claims_proof,
    //     &key,
    //     AboutVerify::with_allowed(application, vec![ActionType::DeleteClaims]),
    // )
    // .map_err(OneOf::broaden)?;

    //let user_id = proof_content.select_one().map_err(OneOf::broaden)?;

    todo!()

    // let write_txn = state
    //     .db()
    //     .begin_write()
    //     .into_one_of::<DbError>()
    //     .map_err(OneOf::broaden)?;

    // {
    //     let mut table = write_txn
    //         .open_table(state.app_tables(application).users())
    //         .into_one_of::<DbError>()
    //         .map_err(OneOf::broaden)?;

    //     let new_login_bytes ={
    //         let login = table
    //         .get(user_id.as_str())
    //         .into_one_of::<DbError>()
    //         .map_err(OneOf::broaden)?;

    //         if let Some(login_bytes) = login {
    //             let login_bytes = login_bytes.value();
    //             let (login_password, claims) = Login::deserialize_tuple(login_bytes);

    //             let proof_claims = proof_content.data.try_deserialize().map_err(|_| OneOf::new(InvalidProof {}))?;

    //             claims.

    //             let new_claims = if proof_content.about.action == ActionType::Set {
    //                 proof_claims.to_claims_sorted().map_err(|_| OneOf::new(ModifyClaimError::NotSorted))?
    //             } else {
    //                 let claims = claims.deserialize();
    //                 let exists_ok = if proof_content.about.action == ActionType::Add {
    //                     false
    //                 } else if proof_content.about.action == ActionType::Merge {
    //                     true
    //                 } else {
    //                     panic!("Only action merge and add allowed!")
    //                 };

    //                 claims.add_claims(proof_claims, exists_ok).to_one_of()
    //                     .map_err(OneOf::broaden)?
    //             };

    //             login_password.into_login(new_claims.serialize().as_packed()).serialize()
    //         } else {
    //             return Err(OneOf::new(ModifyClaimError::UserNotFound))
    //         }
    //     };

    //     table.insert(user_id.as_str(), new_login_bytes.as_slice())
    //     .into_one_of::<DbError>()
    //         .map_err(OneOf::broaden)?;

    // }

    // Ok(())
}

// fn remove_reset_claims(
//     state: &impl State,
//     application: &str,
//     claims_proof: &Proof<ClaimKeys>,
// ) -> Result<(), OneOf<(InvalidProof, DbError)>> {
//     let key = state.app_key(application);
//     let proof_content = verify_proof_content(
//         claims_proof,
//         &key,
//         AboutVerify::with_allowed(
//             application,
//             vec![
//                 ActionType::Delete,
//                 ActionType::Reset,
//             ],
//         ),
//     )
//     .map_err(OneOf::broaden)?;

//     let user_id = proof_content.select_one().map_err(OneOf::broaden)?;

//     let write_txn = state
//         .db()
//         .begin_write()
//         .into_one_of::<DbError>()
//         .map_err(OneOf::broaden)?;

//     {
//         let mut table = write_txn
//             .open_table(state.app_tables(application).users())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;

//         let login = table
//             .get(user_id.as_str())
//             .into_one_of::<DbError>()
//             .map_err(OneOf::broaden)?;

//         if let Some(login_bytes) = login {
//             let login_bytes = login_bytes.value();
//             let (login_password, claims) = Login::deserialize_tuple(login_bytes);
//             let claims = claims.deserialize();
//         } else {

//         }
//     }

//     ()
// }

#[cfg(test)]
mod tests {

    use super::*;
    use crate::data::{BytePacked, SessionClaims, Target, TargetList};
    use crate::ops::login::test_util::*;
    use crate::ops::register::test_util::*;
    use crate::proof::create_proof;
    use crate::state::test_util::TestState;

    #[test]
    fn test_reset_password() {
        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        register_flow(&state, user_id, app, password, None, None);
        let key = state.proof_key(app);
        let proof = create_proof(
            app,
            1800,
            ActionType::ResetPassword,
            Target::Select,
            TargetList::user(user_id),
            BytePacked::empty(),
            key,
        );

        let nonce = reset_password(&state, app, &proof).unwrap();

        let login = get_login(&state, app, user_id).unwrap().unwrap();

        let start_pass = login.password_file;

        register_flow(&state, user_id, app, password, Some(nonce), None);

        let login = get_login(&state, app, user_id).unwrap().unwrap();

        assert!(start_pass != login.password_file);
    }

    #[test]
    fn test_change_password() {
        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        let session =
            login_create_session(&state, user_id, app, password, None, SessionClaims::All);

        let nonce = change_password(&state, &session).unwrap();

        let login = get_login(&state, app, user_id).unwrap().unwrap();
        let initial_pw_file = login.password_file;

        assert_ne!(initial_pw_file, "");

        register_flow(&state, user_id, app, password, Some(nonce), None);

        let login = get_login(&state, app, user_id).unwrap().unwrap();

        assert_ne!(initial_pw_file, login.password_file);
    }

    #[test]
    fn test_delete_passsword() {
        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        let state = TestState::setup_test(vec![app]);

        let session =
            login_create_session(&state, user_id, app, password, None, SessionClaims::All);

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

        let key = state.proof_key(app);
        let proof = create_proof(
            app,
            1800,
            ActionType::DeleteUser,
            Target::Select,
            TargetList::user(user_id),
            BytePacked::empty(),
            key,
        );

        app_delete_user(&state, app, &proof).unwrap();

        let login = get_login(&state, app, user_id).unwrap();

        assert!(login.is_none());
    }
}
