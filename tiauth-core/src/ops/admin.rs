use crate::data::{
    set_login_field_write, LoginFieldError, SetLoginOptions, StateEntry, StateType, Tables,
};
use crate::error::{OneOfTo, WrapErrorOneOf};
use crate::ops::prove::verify_proof_write;
use crate::state::State;
use crate::util::nonce_384;
use redb::{Error as DbError, ReadableTable};
use std::time::SystemTime;
use terrors::OneOf;

use super::prove::{
    verify_proof_meta, verify_session, InvalidProof, Proof, ProofScopeType, CHANGE_AGE, DELETE_AGE,
    LEEWAY,
};

pub fn get_users_encoded(
    state: &impl State,
    proof: Proof,
) -> Result<Vec<Vec<u8>>, OneOf<(DbError, InvalidProof)>> {
    let (proof_info, _) =
        verify_proof_meta(state, proof, ProofScopeType::ReadAll).map_err(OneOf::broaden)?;

    let tables = state.tables().app(&proof_info.application);

    let write_txn = state.db().begin_write().to_one_of_two()?;

    {
        verify_proof_write(state, &write_txn, &proof_info).map_err(OneOf::broaden)?;
    }

    write_txn.commit().to_one_of_two()?;

    let read_txn = state.db().begin_read().to_one_of_two()?;

    let user_table = read_txn.open_table(tables.users()).to_one_of_two()?;

    let mut users: Vec<Vec<u8>> = Vec::new();

    for u in user_table.iter().to_one_of_two()? {
        let (_, user_encoded) = u.to_one_of_two()?;

        users.push(user_encoded.value().to_vec())
    }

    Ok(users)
    
}