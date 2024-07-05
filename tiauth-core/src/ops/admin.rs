use std::iter::Peekable;
use std::vec::IntoIter;

use crate::data::{AboutVerify, ActionType, InvalidProof, Login, LoginPassword, Target};
use crate::error::WrapErrorOneOf;
use crate::ops::verify::verify_proof_write;
use crate::proof::verify_proof_content;
use crate::state::State;
use crate::{Proof, Tables};
use redb::{Error as DbError, ReadableTable};
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteBuf, Bytes};
use terrors::OneOf;

#[derive(Debug, Serialize)]
pub struct UserList {
    users: Vec<ByteBuf>
}

#[derive(Debug, Serialize)]
struct User<'a> {
    user_id: &'a str,
}

#[derive(Debug, Serialize)]
struct UserClaims<'a> {
    user_id: &'a str,
    #[serde(with = "serde_bytes")]
    claims: &'a [u8]
}

pub fn get_users_bytes(
    state: &impl State,
    application: &str,
    include_claims: bool,
    proof: &Proof<()>,
) -> Result<UserList, OneOf<(DbError, InvalidProof)>> {
    let key = state.app_key(application);
    let mut proof_content =
        verify_proof_content(proof, &key, AboutVerify::new(application, ActionType::Read))
            .map_err(OneOf::broaden)?;

    

    let tables = state.tables().app(application);

    let write_txn = state.db().begin_write().to_one_of_two()?;

    {
        verify_proof_write(state, &write_txn, &mut proof_content).map_err(OneOf::broaden)?;
    }

    write_txn.commit().to_one_of_two()?;

    let read_txn = state.db().begin_read().to_one_of_two()?;

    let user_table = read_txn.open_table(tables.users()).to_one_of_two()?;

    let mut users: Vec<ByteBuf> = Vec::new();

    // None here corresponds to selecting all!
    let (user_selection, is_range) = match proof_content.about.target {
        Target::Select =>  (Some(proof_content.target_data.as_vec()), false),
        Target::Range => {
            let mut targets = proof_content.target_data.as_vec();
            if targets.len() != 2 {
                return Err(OneOf::new(InvalidProof {}))
            }
            let last = targets.pop().unwrap();
            let first = targets.pop().unwrap();

            (Some(vec![first, last]), true)
        }
        Target::All => (None, false)
    };

    // Now None user_selection corresponds to not having to check anything in the iter
    let iter= if let Some(user_selection) = &user_selection {
        if user_selection.len() == 0 {
            return Err(OneOf::new(InvalidProof {}))
        }

        let first = user_selection.first().unwrap();
        let last = user_selection.last().unwrap();

        user_table.range(first.as_str()..=last.as_str()).to_one_of_two()?

    } else {
        user_table.iter().to_one_of_two()?
    };
    // let iter_second = iter.clone().map(|v| {
    //     v.unwrap().0.value().to_owned()
    // });
    // println!("iter: {:?}", iter_second.collect::<Vec<String>>());

    let filter_selection = user_selection.is_some() && !is_range;
    let user_selection = if filter_selection { user_selection.unwrap() } else { Vec::new() };

    let mut sel_i = 0;
    for maybe_user in iter {
        let (_, u) = maybe_user.to_one_of_two()?;

        let user_value = u.value();
        // If claims is None, then include_claims was false
        let (user_id, claims) = if include_claims {
            let login = Login::deserialize(user_value);
            (login.user_id, Some(login.claims))
        } else {
            let login = LoginPassword::deserialize_from_login(user_value);
            (login.user_id, None)
        };


        if sel_i < user_selection.len() {
            let next_selected = user_selection[sel_i].as_str();
            if sel_i > 0 && user_selection[sel_i-1].as_str() > next_selected {
                panic!("Selection is not sorted!")
            }
            
            if user_id != next_selected {
                // We do not want this user, so continue
                continue;
            } else {
                // Advance
                sel_i += 1;
            }
        } else if filter_selection {
            // No more to select, we are finished
            break
        }


        let user_bytes = if let Some(claims) = claims {
            let user_claims = UserClaims { user_id: &user_id, claims: claims.as_bytes() };
            rmp_serde::to_vec(&user_claims).unwrap()
        } else {
            let user = User { user_id: &user_id };
            rmp_serde::to_vec(&user).unwrap()
        };

        users.push(ByteBuf::from(user_bytes))
    }

    Ok(UserList { users })
}