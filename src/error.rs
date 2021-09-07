use rusqlite::Error as sqlError;
use std::error;
use warp::http::StatusCode;
use crate::{Serialize};
use log;
use warp::reject::IsReject;

pub trait RejectType {
    fn code(&self) -> u16;

    fn name(&self) -> &'static str;
}

/// Enum listing possible request reject reasons for tiauth server requests.
#[derive(Debug)]
pub enum RejectTypes {
    /// Used for various database and IO-related errors.
    IO,
    /// Used as catch-all internal rusqlite database error.
    SQL,
    Permission,
    AlreadyExists,
    NonExistent,
    DecodeInternal,
    DecodeExternal,
    Tampered,
    Incorrect,
    Internal,
}

impl RejectType for RejectTypes {
    /// Matches each [`RejectTypes`] into corresponding HTTP error code.
    fn code(&self) -> u16 {
        match *self {
            RejectTypes::IO => 500,
            RejectTypes::SQL => 500,
            RejectTypes::Permission => 401,
            RejectTypes::AlreadyExists => 409,
            RejectTypes::NonExistent => 404,
            RejectTypes::DecodeInternal => 500,
            RejectTypes::DecodeExternal => 400,
            RejectTypes::Tampered => 400,
            RejectTypes::Incorrect => 400,
            RejectTypes::Internal => 500,
        }
    }

    /// Returns corresponding string message for each [`RejectTypes`].
    fn name(&self) -> &'static str {
        match *self {
            RejectTypes::IO => "IO Reject",
            RejectTypes::SQL => "SQL Error Reject",
            RejectTypes::Permission => "Permission Reject",
            RejectTypes::AlreadyExists => "Already Exists Reject",
            RejectTypes::NonExistent => "Nonexistent Reject",
            RejectTypes::DecodeInternal => "Decode Internal Reject",
            RejectTypes::DecodeExternal => "Decode External Reject",
            RejectTypes::Tampered => "Tampered Reject",
            RejectTypes::Incorrect => "Incorrect Input Reject",
            RejectTypes::Internal => "Internal Error Reject"
        }
    }
}

/// Used to capture `tiauth` errors.
/// # Fields
/// * `rt` - Custom [`RejectTypes`] that contains a message and HTTP code.
/// * `msg` - Custom message that is included in the response.
/// * `e` - Internal error message, usually string representation of underlying error. If handled by
/// ['handle_rejection`], string components between '@@@' (can be more than one) will be included in
/// the response.
///
#[derive(Debug)]
pub struct ErrorReject { pub rt: RejectTypes, pub msg: &'static str, pub e: String }

impl warp::reject::Reject for ErrorReject {}

/// Trait extension to allow less verbose error mapping from results if they must be mapped to
/// `warp::Rejection` errors.
pub trait RejectableExt<T, E: error::Error> {
    fn rej(self, rt: RejectTypes, msg: &'static str) -> Result<T, ErrorReject>;
}

impl<T, E: error::Error> RejectableExt<T, E> for Result<T, E> {
    /// Maps `Result<T, E>` to a `Result<T, `[ErrorReject]`>` with the internal error converted to
    /// its string representation.
    ///
    /// # Examples
    ///
    /// Original code:
    ///
    /// ```
    /// # use tiauth::error::{ErrorReject, RejectTypes};
    /// # use hex;
    /// # use warp::reject;
    /// fn reply_hex_bytes(hex_string: &str)
    ///     -> Result<Vec<u8>, warp::Rejection> {
    ///
    ///     let bytes = hex::decode(hex_string).map_err(|e| { reject::custom(ErrorReject {
    ///             rt: RejectTypes::DecodeInternal,
    ///             msg: "Error decoding hex!",
    ///             e: e.to_string()
    ///     }) })?;
    ///
    ///     Ok(bytes)
    /// }
    /// ```
    ///
    /// Shorter code:
    /// ```
    /// # use tiauth::error::{ErrorReject, RejectTypes, RejectableExt};
    /// # use hex;
    /// fn reply_hex_bytes(hex_string: &str)
    ///     -> Result<Vec<u8>, warp::Rejection> {
    ///
    ///     let bytes = hex::decode(hex_string)
    ///         .rej(RejectTypes::DecodeInternal, "Error decoding hex!")?;
    ///
    ///     Ok(bytes)
    /// }
    /// ```
    fn rej(self, rt: RejectTypes, msg: &'static str) -> Result<T, ErrorReject> {
        self.map_err(|e| ErrorReject {
            rt,
            msg,
            e: e.to_string()
        })
    }
}

/// Used to pass additional message to request/response function about an internal `rusqlite` error.
pub struct RusqliteErrorPass {
    pub rusqlite_error: sqlError,
    internal_msg: String
}

/// Trait extension to convert `rusqlite::Error` into a [`RusqliteErrorPass`] with additional info.
pub trait RusqliteResultExt<T> {
    fn err_pass(self, msg: &'static str) -> Result<T, RusqliteErrorPass>;
}

impl<T> RusqliteResultExt<T> for Result<T, sqlError> {
    /// Maps internal `rusqlite::Error` to a [`RusqliteErrorPass`], which can then be used by outer
    /// request/response function.
    fn err_pass(self, msg: &'static str) -> Result<T, RusqliteErrorPass> {
        self.map_err(|e: sqlError| {
            RusqliteErrorPass {
                rusqlite_error: e,
                internal_msg: msg.to_owned()
            }
        })
    }
}

/// Trait extension equivalent to [`RejectableExt`] for use with internal `rusqlite::Error`s. Uses
/// [`RusqliteErrorPass`] for additional information about which inner function caused the error.
pub trait RusqliteErrorPassExt<T> {
    fn sql_rej(self, msg: &'static str) -> Result<T, ErrorReject>;
}

impl<T> RusqliteErrorPassExt<T> for Result<T, RusqliteErrorPass> {
    /// Maps `Result<T, rusqlite::Error>` to a `Result<T, `[ErrorReject]`>`, similar to `rej` from
    /// [`RejectableExt`], but with additional logic to set correct [`RejectTypes`] for different
    /// internal errors as well as using the [`RusqliteErrorPass`]'s additional error info.
    fn sql_rej(self, msg: &'static str) -> Result<T, ErrorReject> {
        self.map_err(|e_pass: RusqliteErrorPass| {
            let e = e_pass.rusqlite_error;

            let rt = match e {
                sqlError::QueryReturnedNoRows => RejectTypes::NonExistent,
                _ => RejectTypes::SQL
            };

            ErrorReject {
                rt,
                msg,
                e: format!("{}, {}", e.to_string(), e_pass.internal_msg)
            }
        })
    }
}

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

pub async fn handle_rejection(err: warp::reject::Rejection) -> Result<impl warp::reply::Reply, warp::Rejection> {
    let code;
    let message: String;
    let error_str: String;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND".to_owned();
        error_str = "".to_string();
    }
    else if let Some(error_reject) = err.find::<ErrorReject>() {
        code = StatusCode::from_u16(error_reject.rt.code()).unwrap();

        // Error messages can be propagated to the requester by putting them in between '@@@' on
        // both sides.
        let split_app = error_reject.e.split("@@@").collect::<Vec<&str>>();
        let n_split = split_app.len();
        let mut msg_apps: Vec<String> = Vec::new();
        let mut err_apps: Vec<String> = Vec::new();
        if n_split % 2 == 1 {
            for (i, e) in split_app.iter().enumerate() {
                if i % 2 == 0 {
                    err_apps.push((*e).to_owned());
                }
                else {
                    msg_apps.push((*e).to_owned())
                }
            }
        }
        else {
            err_apps.push(error_reject.e.clone());
        }
        let msg_apps = msg_apps.join(" ");
        let err_apps = err_apps.join(" ");

        message = format!("{}: {} {}", error_reject.rt.name(), error_reject.msg, msg_apps);

        error_str = err_apps
    }
    else {
        code = err.status();
        message = format!("UNHANDLED {:?}", err);
        error_str = "".to_string();
    }

    let error_message = &ErrorMessage {
        code: code.as_u16(),
        message: message.to_owned(),
    };

    let j = warp::reply::json(&error_message);

    if error_message.code >= 500 {
        log::error!("Rejection {}: {}", code, message);
        log::error!("Err: {}", error_str);
    }
    else if error_message.code >= 400 {
        log::debug!("Rejection {}: {}", code, message);
        log::debug!("Err: {}", error_str);
    }
    else {
        log::trace!("Rejection {}: {}", code, message);
        log::trace!("Err: {}", error_str);
    }


    Ok(warp::reply::with_status(j, code))
}