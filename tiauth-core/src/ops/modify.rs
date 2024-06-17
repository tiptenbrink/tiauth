use crate::crypto::verify_signature;
use crate::data::{app_key, set_login_field_write, state_table};
use crate::ops::prove::proof_data;
use crate::state::State;
use base64::{engine::general_purpose as b64, Engine as _};
use redb::{Error, ReadableTable};
use std::time::SystemTime;

use super::prove::{Proof, ProofUse, LEEWAY};

fn reset_password(state: &mut State, proof: Proof) -> Result<(), Error> {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > proof.expires + LEEWAY {
        panic!("Proof has expired!");
    }

    if let ProofUse::ResetPassword(user_id) = proof.proof_use {
        let state_table_def = state_table(state.tables, &proof.application);
        let signature = b64::URL_SAFE_NO_PAD.decode(&proof.signature).unwrap();

        let write_txn = state.db.begin_write()?;
        {
            let state_table = write_txn.open_table(state_table_def)?;

            // TODO clean up nonces every so often (after expiry)
            let nonce_exists = state_table.get(proof.nonce.as_str())?;

            if nonce_exists.is_some() {
                panic!("Proof has already been used!");
            }

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

            assert!(set_login_field_write(
                &write_txn,
                state,
                &proof.application,
                &user_id,
                "".to_owned(),
                false
            )?)
        }
        write_txn.commit()?;
    } else {
        // TODO make error
        panic!("Proof for reset password must be reset_password!")
    }

    Ok(())
}
