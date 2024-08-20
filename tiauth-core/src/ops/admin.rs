use crate::data::UserPassword;
use crate::error::OneOfTo;
use crate::proof::{InvalidProof, ProofTargetAny, ProofTargetOut};
use crate::state::State;
use crate::store::ReadableTable;
use crate::{error::WrapErrorOneOf, store::StoreError};
use crate::{ActionType, Proof};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use terrors::OneOf;

use super::verify::verify_proof;

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
    proof: &Proof<()>,
) -> Result<UserList, OneOf<(StoreError, InvalidProof)>> {
    let time = state.time();
    let proof_unvalidated = verify_proof(state, proof, time).map_err(OneOf::broaden)?;

    let (_, targets) = proof_unvalidated
        .validate(ActionType::ReadUsers, ProofTargetAny)
        .to_one_of()
        .map_err(OneOf::broaden)?;

    let tx = state
        .store()
        .open_read()
        .to_one_of()
        .map_err(OneOf::broaden)?;

    let user_table = tx.user_table().to_one_of().map_err(OneOf::broaden)?;

    let mut users: Vec<ByteBuf> = Vec::new();

    // Now None user_selection corresponds to not having to check anything in the iter
    let (iter, filter_selection, user_selection) = match targets {
        ProofTargetOut::Range((first, last)) => {
            if first > last {
                panic!("Selection or range is not sorted!")
            }

            (
                user_table
                    .range(first.as_str()..=last.as_str())
                    .to_one_of_two()?,
                false,
                Vec::new(),
            )
        }
        ProofTargetOut::Select(select) => (user_table.iter().to_one_of_two()?, true, select),
        ProofTargetOut::All => (user_table.iter().to_one_of_two()?, false, Vec::new()),
    };

    let mut sel_i = 0;
    for user in iter {
        let user_value = user.1.value();
        // If claims is None, then include_claims was false
        let login = UserPassword::deserialize(user_value);

        if sel_i < user_selection.len() {
            let next_selected = user_selection[sel_i].as_str();
            if sel_i > 0 && user_selection[sel_i - 1].as_str() > next_selected {
                panic!("Selection is not sorted!")
            }

            if login.user_id != next_selected {
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

        users.push(ByteBuf::from(user_value.to_vec()))
    }

    Ok(UserList { users })
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::{
//         data::Login, proof::create_proof, store::set_login, test::TestState, BytePacked,
//         ByteSerial, Claims, TargetList,
//     };

//     fn parse_user_list(user_list: UserList) -> Vec<String> {
//         user_list
//             .users
//             .into_iter()
//             .map(|u| {
//                 rmp_serde::from_slice::<User>(u.as_slice())
//                     .unwrap()
//                     .user_id
//                     .to_owned()
//             })
//             .collect()
//     }

//     fn setup_users(state: &impl State, application: &str) {
//         let claims = Claims::empty().serialize();

//         let user_1 = Login {
//             user_id: "1".to_owned(),
//             password_file: "pw".to_owned(),
//             claims: claims.as_packed(),
//         };
//         let user_2 = Login {
//             user_id: "a".to_owned(),
//             password_file: "pw".to_owned(),
//             claims: claims.as_packed(),
//         };
//         let user_3 = Login {
//             user_id: "de".to_owned(),
//             password_file: "pw".to_owned(),
//             claims: claims.as_packed(),
//         };
//         let user_4 = Login {
//             user_id: "df".to_owned(),
//             password_file: "pw".to_owned(),
//             claims: claims.as_packed(),
//         };

//         set_login(state, &user_1, application).unwrap();
//         set_login(state, &user_2, application).unwrap();
//         set_login(state, &user_3, application).unwrap();
//         set_login(state, &user_4, application).unwrap();
//     }

//     #[test]
//     fn test_filter() {
//         let state = TestState::setup_test(vec!["app"]);

//         setup_users(&state, "app");

//         let action = ActionType::ReadUsers;

//         let key = state.proof_key("app");
//         let empty_data = BytePacked::new(&[]);

//         let proof: Proof<()> = create_proof(
//             "app",
//             1800,
//             action.clone(),
//             Target::Select,
//             TargetList::new(vec!["a"]),
//             empty_data,
//             key,
//         );
//         let one_user = get_users_bytes(&state, "app", false, &proof).unwrap();
//         let user_ids = parse_user_list(one_user);
//         assert_eq!(vec!["a"], user_ids);

//         let proof: Proof<()> = create_proof(
//             "app",
//             1800,
//             action.clone(),
//             Target::Select,
//             TargetList::new(vec!["1", "a", "z"]),
//             empty_data,
//             key,
//         );
//         let user_more = get_users_bytes(&state, "app", false, &proof).unwrap();
//         let user_ids = parse_user_list(user_more);
//         assert_eq!(vec!["1", "a"], user_ids);

//         let proof: Proof<()> = create_proof(
//             "app",
//             1800,
//             action.clone(),
//             Target::Select,
//             TargetList::new(vec!["xyz"]),
//             empty_data,
//             key,
//         );
//         let user_not_exists = get_users_bytes(&state, "app", false, &proof).unwrap();
//         let user_ids = parse_user_list(user_not_exists);
//         assert_eq!(Vec::<String>::new(), user_ids);

//         let proof: Proof<()> = create_proof(
//             "app",
//             1800,
//             action,
//             Target::Range,
//             TargetList::new(vec!["a", "df"]),
//             empty_data,
//             key,
//         );
//         let user_range = get_users_bytes(&state, "app", false, &proof).unwrap();
//         let user_ids = parse_user_list(user_range);
//         assert_eq!(vec!["a", "de", "df"], user_ids);
//     }

//     #[test]
//     #[should_panic(expected = "Selection is not sorted!")]
//     fn test_not_sorted() {
//         let state = TestState::setup_test(vec!["app"]);

//         setup_users(&state, "app");

//         let action = ActionType::ReadUsers;

//         let key = state.proof_key("app");
//         let empty_data = BytePacked::new(&[]);

//         let proof: Proof<()> = create_proof(
//             "app",
//             1800,
//             action,
//             Target::Select,
//             TargetList::new(vec!["a", "1", "z"]),
//             empty_data,
//             key,
//         );
//         let one_user = get_users_bytes(&state, "app", false, &proof).unwrap();
//         let _ = parse_user_list(one_user);
//     }

//     #[test]
//     #[should_panic(expected = "Selection or range is not sorted!")]
//     fn test_not_sorted_range() {
//         let state = TestState::setup_test(vec!["app"]);

//         setup_users(&state, "app");

//         let action = ActionType::ReadUsers;

//         let key = state.proof_key("app");
//         let empty_data = BytePacked::new(&[]);

//         let proof: Proof<()> = create_proof(
//             "app",
//             1800,
//             action,
//             Target::Select,
//             TargetList::new(vec!["d", "a"]),
//             empty_data,
//             key,
//         );
//         let one_user = get_users_bytes(&state, "app", false, &proof).unwrap();
//         let _ = parse_user_list(one_user);
//     }
// }
