use crate::crypto::verify_signature;
use crate::data::{app_key, set_login_field_write, state_table};
use crate::ops::prove::proof_data;
use crate::state::State;
use crate::util::nonce_384;
use base64::{engine::general_purpose as b64, Engine as _};
use redb::{Error, ReadableTable};
use std::time::SystemTime;

use super::prove::{Proof, ProofUse, LEEWAY};

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
fn reset_password(state: &mut State, proof: Proof) -> Result<String, Error> {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > proof.expires + LEEWAY {
        panic!("Proof has expired!");
    }

    let change_nonce = if let ProofUse::ResetPassword(user_id) = proof.proof_use {
        let signature = b64::URL_SAFE_NO_PAD.decode(&proof.signature).unwrap();

        let key = app_key(state, &proof.application)?;

        let is_verified = verify_signature(
            &proof_data(
                &proof.application,
                &proof.nonce,
                proof.expires,
                &ProofUse::ResetPassword(user_id.clone()),
            ),
            &signature,
            key,
        );

        if !is_verified {
            panic!("Signature invalid!");
        }

        let state_table_def = state_table(state.tables, &proof.application);

        // 10 minutes
        let change_expires = format!("{}", time + 1800);
        let change_nonce = format!("{}:change:{}", user_id, nonce_384(state.rng));

        let write_txn = state.db.begin_write()?;
        {
            let mut state_table = write_txn.open_table(state_table_def)?;
            {
                // TODO clean up nonces every so often (after expiry)
                let nonce_exists = state_table.get(proof.nonce.as_str())?;

                if nonce_exists.is_some() {
                    panic!("Proof has already been used!");
                }
            }

            let proof_expires = format!("{}", proof.expires);
            state_table.insert(proof.nonce.as_str(), proof_expires.as_str())?;

            assert!(set_login_field_write(
                &write_txn,
                state,
                &proof.application,
                &user_id,
                "".to_owned(),
                false
            )?);

            state_table.insert(change_nonce.as_str(), change_expires.as_str())?;
        }
        write_txn.commit()?;

        change_nonce
    } else {
        // TODO make error
        panic!("Proof for reset password must be reset_password!")
    };

    Ok(change_nonce)
}
