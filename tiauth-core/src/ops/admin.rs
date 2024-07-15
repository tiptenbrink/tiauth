use crate::data::{AboutVerify, ActionType, InvalidProof, Login, LoginPassword, Target};
use crate::error::WrapErrorOneOf;
use crate::ops::verify::verify_proof_write;
use crate::proof::verify_proof_content;
use crate::state::State;
use crate::Proof;
use redb::{Error as DbError, ReadableTable};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use terrors::OneOf;

#[derive(Debug, Serialize)]
pub struct UserList {
    users: Vec<ByteBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
struct User<'a> {
    user_id: &'a str,
}

#[derive(Debug, Serialize)]
struct UserClaims<'a> {
    user_id: &'a str,
    #[serde(with = "serde_bytes")]
    claims: &'a [u8],
}

pub fn get_users_bytes(
    state: &impl State,
    application: &str,
    include_claims: bool,
    proof: &Proof<()>,
) -> Result<UserList, OneOf<(DbError, InvalidProof)>> {
    let key = state.app_key(application);
    let mut proof_content =
        verify_proof_content(proof, &key, AboutVerify::new(application, ActionType::ReadUsers))
            .map_err(OneOf::broaden)?;

    let tables = state.app_tables(application);

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
        Target::Select => (Some(proof_content.target_data.as_vec()), false),
        Target::Range => {
            let mut targets = proof_content.target_data.as_vec();
            if targets.len() != 2 {
                return Err(OneOf::new(InvalidProof {}));
            }
            let last = targets.pop().unwrap();
            let first = targets.pop().unwrap();

            (Some(vec![first, last]), true)
        }
        Target::All => (None, false),
    };

    // Now None user_selection corresponds to not having to check anything in the iter
    let iter = if let Some(user_selection) = &user_selection {
        if user_selection.is_empty() {
            return Err(OneOf::new(InvalidProof {}));
        }

        let first = user_selection.first().unwrap();
        let last = user_selection.last().unwrap();

        if first > last {
            panic!("Selection or range is not sorted!")
        }

        user_table
            .range(first.as_str()..=last.as_str())
            .to_one_of_two()?
    } else {
        user_table.iter().to_one_of_two()?
    };

    let filter_selection = user_selection.is_some() && !is_range;
    let user_selection = if filter_selection {
        user_selection.unwrap()
    } else {
        Vec::new()
    };

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
            if sel_i > 0 && user_selection[sel_i - 1].as_str() > next_selected {
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
            break;
        }

        let user_bytes = if let Some(claims) = claims {
            let user_claims = UserClaims {
                user_id: &user_id,
                claims: claims.as_bytes(),
            };
            rmp_serde::to_vec(&user_claims).unwrap()
        } else {
            let user = User { user_id: &user_id };
            rmp_serde::to_vec(&user).unwrap()
        };

        users.push(ByteBuf::from(user_bytes))
    }

    Ok(UserList { users })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        data::Login, proof::create_proof, store::set_login, test::TestState, BytePacked,
        ByteSerial, Claims, TargetList,
    };

    fn parse_user_list(user_list: UserList) -> Vec<String> {
        user_list
            .users
            .into_iter()
            .map(|u| {
                rmp_serde::from_slice::<User>(u.as_slice())
                    .unwrap()
                    .user_id
                    .to_owned()
            })
            .collect()
    }

    fn setup_users(state: &impl State, application: &str) {
        let claims = Claims::empty().serialize();

        let user_1 = Login {
            user_id: "1".to_owned(),
            password_file: "pw".to_owned(),
            claims: claims.as_packed(),
        };
        let user_2 = Login {
            user_id: "a".to_owned(),
            password_file: "pw".to_owned(),
            claims: claims.as_packed(),
        };
        let user_3 = Login {
            user_id: "de".to_owned(),
            password_file: "pw".to_owned(),
            claims: claims.as_packed(),
        };
        let user_4 = Login {
            user_id: "df".to_owned(),
            password_file: "pw".to_owned(),
            claims: claims.as_packed(),
        };

        set_login(state, &user_1, application).unwrap();
        set_login(state, &user_2, application).unwrap();
        set_login(state, &user_3, application).unwrap();
        set_login(state, &user_4, application).unwrap();
    }

    #[test]
    fn test_filter() {
        let state = TestState::setup_test(vec!["app"]);

        setup_users(&state, "app");

        let action = ActionType::ReadUsers;

        let key = state.proof_key("app");
        let empty_data = BytePacked::new(&[]);

        let proof: Proof<()> = create_proof(
            "app",
            1800,
            action.clone(),
            Target::Select,
            TargetList::new(vec!["a"]),
            empty_data,
            key,
        );
        let one_user = get_users_bytes(&state, "app", false, &proof).unwrap();
        let user_ids = parse_user_list(one_user);
        assert_eq!(vec!["a"], user_ids);

        let proof: Proof<()> = create_proof(
            "app",
            1800,
            action.clone(),
            Target::Select,
            TargetList::new(vec!["1", "a", "z"]),
            empty_data,
            key,
        );
        let user_more = get_users_bytes(&state, "app", false, &proof).unwrap();
        let user_ids = parse_user_list(user_more);
        assert_eq!(vec!["1", "a"], user_ids);

        let proof: Proof<()> = create_proof(
            "app",
            1800,
            action.clone(),
            Target::Select,
            TargetList::new(vec!["xyz"]),
            empty_data,
            key,
        );
        let user_not_exists = get_users_bytes(&state, "app", false, &proof).unwrap();
        let user_ids = parse_user_list(user_not_exists);
        assert_eq!(Vec::<String>::new(), user_ids);

        let proof: Proof<()> = create_proof(
            "app",
            1800,
            action,
            Target::Range,
            TargetList::new(vec!["a", "df"]),
            empty_data,
            key,
        );
        let user_range = get_users_bytes(&state, "app", false, &proof).unwrap();
        let user_ids = parse_user_list(user_range);
        assert_eq!(vec!["a", "de", "df"], user_ids);
    }

    #[test]
    #[should_panic(expected = "Selection is not sorted!")]
    fn test_not_sorted() {
        let state = TestState::setup_test(vec!["app"]);

        setup_users(&state, "app");

        let action = ActionType::ReadUsers;

        let key = state.proof_key("app");
        let empty_data = BytePacked::new(&[]);

        let proof: Proof<()> = create_proof(
            "app",
            1800,
            action,
            Target::Select,
            TargetList::new(vec!["a", "1", "z"]),
            empty_data,
            key,
        );
        let one_user = get_users_bytes(&state, "app", false, &proof).unwrap();
        let _ = parse_user_list(one_user);
    }

    #[test]
    #[should_panic(expected = "Selection or range is not sorted!")]
    fn test_not_sorted_range() {
        let state = TestState::setup_test(vec!["app"]);

        setup_users(&state, "app");

        let action = ActionType::ReadUsers;

        let key = state.proof_key("app");
        let empty_data = BytePacked::new(&[]);

        let proof: Proof<()> = create_proof(
            "app",
            1800,
            action,
            Target::Select,
            TargetList::new(vec!["d", "a"]),
            empty_data,
            key,
        );
        let one_user = get_users_bytes(&state, "app", false, &proof).unwrap();
        let _ = parse_user_list(one_user);
    }
}
