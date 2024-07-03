use crate::ops::prove::verify_proof_write;
use crate::state::State;
use crate::Tables;
use crate::{error::WrapErrorOneOf, prove::Proof};
use redb::{Error as DbError, ReadableTable};
use terrors::OneOf;

use super::prove::verify_proof_content;
use crate::data::{AboutVerify, ActionType, InvalidProof, Target};

pub fn get_users_encoded(
    state: &impl State,
    application: &str,
    proof: &Proof<()>,
) -> Result<Vec<Vec<u8>>, OneOf<(DbError, InvalidProof)>> {
    let key = state.app_key(application);
    let mut proof_content =
        verify_proof_content(proof, &key, AboutVerify::new(application, ActionType::Read))
            .map_err(OneOf::broaden)?;

    if proof_content.about.target != Target::All {
        return Err(OneOf::new(InvalidProof {}));
    }

    let tables = state.tables().app(application);

    let write_txn = state.db().begin_write().to_one_of_two()?;

    {
        verify_proof_write(state, &write_txn, &mut proof_content).map_err(OneOf::broaden)?;
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
