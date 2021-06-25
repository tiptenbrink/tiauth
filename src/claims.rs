use crate::{files, defs, auth};
use crate::error::{ErrorReject, RejectTypes};
use crate::{Deserialize, Serialize};
use crate::reject;
use log::debug;

#[derive(Deserialize, Serialize)]
struct InvalidTargetsResponse {
    invalid_targets: Vec<(String, String)>,
}

#[derive(Deserialize, Serialize)]
pub struct NewUserClaim {
    origin: String,
    anphd_id: String,
    uuid: String,
    writer_permission: u16,
    target_user_hex: String,
    target_permission: u16,
    jwt: String,
}

#[derive(Deserialize, Serialize)]
struct ClaimTarget {
    target_user_hex: String,
    target_permission: u16,
}

#[derive(Deserialize, Serialize)]
pub struct UserClaimWrite {
    origin: String,
    anphd_id: String,
    writer: String,
    uuid: String,
    targets: Vec<ClaimTarget>,
    jwt: String,
}

pub async fn new_user_claim(
    new_user_claim: NewUserClaim) -> Result<impl warp::Reply, warp::Rejection> {

    auth::verify_jwt(&new_user_claim.origin, &new_user_claim.jwt).await?;

    let resources = files::open_resources().await
        .map_err(|e| { reject(ErrorReject { rt: RejectTypes::IO, msg: "Error reading resources (new user claim)", e: e.to_string()}) })?;
    let mut resources_arr = resources.resources;

    let id = new_user_claim.origin.clone() + ":" + &new_user_claim.anphd_id.clone();

    if resources_arr.contains(&id) {
        let appendix = format!("@@@resource_id: {}@@@", &id);
        Err(reject(ErrorReject { rt: RejectTypes::AlreadyExists, msg: "Resource already exists! (new user claim):", e: appendix}))
    }
    else {
        resources_arr.push(id);

        modify_user_claim(new_user_claim, true).await?;

        files::write_new_user_resource(resources_arr).await
            .map_err(|e| { reject(ErrorReject { rt: RejectTypes::IO, msg: "Error writing new resource (new user claim)", e: e.to_string()}) })?;

        Ok(warp::reply())
    }
}

/// Writes a resource user claim to one or more targets.
pub async fn modify_user_claims(
    user_claim_write: UserClaimWrite) -> Result<impl warp::Reply, warp::Rejection> {

    auth::verify_jwt(&user_claim_write.writer, &user_claim_write.jwt).await?;

    let writer_claims = files::read_user_claims(&user_claim_write.writer).await
        .map_err(|e| { files::io_nonexistent_reject(e, "Error reading user writer claims (modify user claims)",
                                                    "Writer user claims do not exist! (modify user claims") })?;

    // Check if claim exists and if writer has actual write access
    // Then checks if the write operation is valid, so if writer has enough permission
    let new_claims = writer_claims.claims.iter().find(|claim| {
        return claim.origin == user_claim_write.origin && claim.anphd_id == user_claim_write.anphd_id;
    })
        .and_then(|claim| Some(claim))
        .map_or_else(|| {
            Err(reject(ErrorReject { rt: RejectTypes::NonExistent, msg: "Writer claim not found (modify user claims)", e: "".to_owned() }))
        },
                     |claim: &defs::UserClaim| {
                         if claim.permission >= 3000 {
                             Err(reject(ErrorReject { rt: RejectTypes::Permission, msg: "No write access to claim (modify user claims)", e: "".to_owned() }))
                         }
                         else {
                             let mut valid_claims: Vec<NewUserClaim> = Vec::new();
                             let mut invalid_claim_targets: Vec<(String, String)> = Vec::new();

                             for target in user_claim_write.targets {
                                 if target.target_permission >= claim.permission {
                                     valid_claims.push(NewUserClaim {
                                         origin: user_claim_write.origin.clone(),
                                         anphd_id: user_claim_write.anphd_id.clone(),
                                         uuid: user_claim_write.uuid.clone(),
                                         writer_permission: claim.permission,
                                         target_user_hex: target.target_user_hex.clone(),
                                         target_permission: target.target_permission.clone(),
                                         jwt: "".to_owned()
                                     });
                                 }
                                 else {
                                     invalid_claim_targets.push((target.target_user_hex.clone(), "Target has better permission than writer".to_owned()));
                                 }
                             }

                             Ok((valid_claims, invalid_claim_targets))
                         }
                     });

    if new_claims.is_ok() {
        let (valid_claims, mut invalid_claim_targets) = new_claims.unwrap();
        let mut some_valid = false;
        for new_claim in valid_claims {
            let target_claims = files::read_user_claims(&new_claim.target_user_hex).await
                .map_err(|e| { files::io_nonexistent_reject(e, "Error reading user target claims (modify user claims)",
                                                            "Target user claims do not exist! (modify user claims") })?;
            if target_claims.claims.iter().find(|claim| {
                return claim.origin == new_claim.origin && claim.anphd_id == new_claim.anphd_id;
            })
                .and_then(|claim| Some(claim.permission))
                .map_or_else(|| {
                    true
                },
                             |current_permission: u16| {
                                 new_claim.writer_permission == 0 || new_claim.writer_permission < current_permission
                             }) {
                modify_user_claim(new_claim, false).await?;
                some_valid = true;
            }
            else {
                invalid_claim_targets.push((new_claim.target_user_hex.clone(), "Target has better permission in claims found or no claims found in target.".to_owned()));
            }
        }
        let invalid_targets_response = InvalidTargetsResponse {
            invalid_targets: invalid_claim_targets
        };
        let j = serde_json::to_string(&invalid_targets_response)
            .map_err(|e| { reject(ErrorReject { rt: RejectTypes::DecodeInternal, msg: "Error converting invalid targets to JSON (modify user claims)", e: e.to_string()}) })?;

        if !some_valid {
            Err(reject(ErrorReject { rt: RejectTypes::Incorrect, msg: "Incorrect claim modifications, no valid claims (modify user claims)", e: format!("@@@{}@@@", j)}))
        }
        else {
            Ok(warp::reply::json(&j))
        }
    }
    else {
        Err(new_claims.err().unwrap())
    }
}

/// Writes a resource user claim to the target in new_user_claim
///
/// This functions assumes the caller has verified the writer as having ownership
/// of the resource. It performs no additional checks of its own.
///
/// Permission is a [`u16`] with various standard levels.
/// - 0 is full ownership and allows removing other owners.
/// - 1-999 is general admin access and nearly complete privileges: 500 admin
/// - 1000-1999 is general managing access: 1500 manager
/// - 2000-2999 is general write access with moderation powers: 2500 moderator
/// - 3000-3999 is general write access without moderation, i.e. above 3000 it is not possible to
/// modify the claims of other users: 3500 write access
/// - 4000-4999 is general read access with limited powers: 4500 read access
/// - 5000: read-only
///
async fn modify_user_claim(
    new_user_claim: NewUserClaim, require_empty: bool) -> Result<impl warp::Reply, warp::Rejection> {

    let mut target_claims = files::read_user_claims(&new_user_claim.target_user_hex).await
        .map_err(|e| { files::io_nonexistent_reject(e, "Error reading user target claims (modify user claim)",
                                                    "Target user claims do not exist! (modify user claim") })?;

    debug!("clms {:?}", target_claims.claims);
    let found = target_claims.claims.iter_mut().find(|claim| {
        return claim.origin == new_user_claim.origin && claim.anphd_id == new_user_claim.anphd_id;
    });
    let exists = found.is_some();

    debug!("fnd {:?}", found);
    let mut new_target_claim = defs::UserClaim {
        origin: new_user_claim.origin.clone(),
        anphd_id: new_user_claim.anphd_id.clone(),
        uuid: new_user_claim.uuid.clone(),
        permission: new_user_claim.target_permission.clone()
    };
    let mut found = found.unwrap_or(&mut new_target_claim);
    if exists {
        found.origin = new_user_claim.origin;
        found.anphd_id = new_user_claim.anphd_id;
        found.uuid = new_user_claim.uuid;
        found.permission = new_user_claim.target_permission;
    }
    else {
        target_claims.claims.push(new_target_claim);
    }

    debug!("{:?}", target_claims.claims);

    files::write_user_claims(&new_user_claim.target_user_hex, &target_claims).await
        .map_err(|e| { reject(ErrorReject{ rt: RejectTypes::IO,
            msg: "Error writing claim to target (modify user claim)", e: e.to_string() }) })?;

    if exists && require_empty {
        Err(reject(ErrorReject{ rt: RejectTypes::Incorrect,
            msg: "Claim already exists, cannot write new (modify user claim)",
            e: "".to_string()
        }))
    }
    else {
        Ok(warp::reply())
    }
}