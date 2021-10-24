use std::error;

use serde::Serialize;
use warp::Reply;
use warp::http::StatusCode;
use warp::reply::Response;

use crate::debug;

pub trait RejectType {
    fn code(&self) -> u16;

    fn name(&self) -> &'static str;
}

pub enum Errors {
    IO,
    Permission,
    AlreadyExists,
    NonExistent,
    DecodeInternal,
    DecodeExternal,
    Tampered,
    Incorrect,
    Internal
}

impl Errors {
    fn status(&self) -> StatusCode {
        match *self {
            Errors::IO => StatusCode::INTERNAL_SERVER_ERROR,
            Errors::Permission => StatusCode::UNAUTHORIZED,
            Errors::AlreadyExists => StatusCode::CONFLICT,
            Errors::NonExistent => StatusCode::NOT_FOUND,
            Errors::DecodeInternal => StatusCode::INTERNAL_SERVER_ERROR,
            Errors::DecodeExternal => StatusCode::BAD_REQUEST,
            Errors::Tampered => StatusCode::BAD_REQUEST,
            Errors::Incorrect => StatusCode::BAD_REQUEST,
            Errors::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn name(&self) -> &'static str {
        match *self {
            Errors::IO => "IO Reject",
            Errors::Permission => "Permission Reject",
            Errors::AlreadyExists => "Already Exists Reject",
            Errors::NonExistent => "Nonexistent Reject",
            Errors::DecodeInternal => "Decode Internal Reject",
            Errors::DecodeExternal => "Decode External Reject",
            Errors::Tampered => "Tampered Reject",
            Errors::Incorrect => "Incorrect Input Reject",
            Errors::Internal => "Internal Error Reject"
        }
    }
}

pub struct TiauthError {
    pub message: &'static str,
    pub error_type: Errors,
    pub e: String
}

#[derive(Serialize)]
struct ErrorReply {
    name: &'static str,
    message: &'static str
}

impl From<&TiauthError> for ErrorReply {
    fn from(e: &TiauthError) -> Self {
        ErrorReply {
            name: e.error_type.name(),
            message: e.message
        }
    }
}

pub trait IntoTiauthError: error::Error {
    fn error_type(&self) -> Errors;
}

impl IntoTiauthError for hex::FromHexError {
    fn error_type(&self) -> Errors { Errors::DecodeInternal }
}

impl IntoTiauthError for diesel::result::Error {
    fn error_type(&self) -> Errors { Errors::Internal }
}

impl Reply for TiauthError {
    fn into_response(self) -> Response {
        let reply = warp::reply::json(&ErrorReply::from(&self));
        let res = warp::reply::with_status(reply, self.error_type.status());
        res.into_response()
    }
}

/// Trait extension to allow less verbose error mapping from results if they must be mapped to
/// `warp::Rejection` errors.
pub trait ErrorExt<T, E: IntoTiauthError> {
    fn repl(self, msg: &'static str) -> Result<T, TiauthError>;
}

impl<T, E: IntoTiauthError> ErrorExt<T, E> for Result<T, E> {
    /// Maps `Result<T, E>` to a `Result<T, `[TiauthError]`>` with the internal error converted to
    /// its string representation. Only works on errors that implement `[IntoTiauthError]`.
    ///
    /// # Examples
    ///
    /// Original code:
    ///
    /// ```
    /// # use hex;
    /// use tiauth::error::{TiauthError, Errors};
    /// fn reply_hex_bytes(hex_string: &str)
    ///     -> Result<Vec<u8>, TiauthError> {
    ///
    ///     let bytes = hex::decode(hex_string).map_err(|e| {
    ///             TiauthError {
    ///                 error_type: Errors::DecodeInternal,
    ///                 message: "Error decoding hex!",
    ///                 e: e.to_string()
    ///             }
    ///     })?;
    ///
    ///     Ok(bytes)
    /// }
    /// ```
    ///
    /// Shorter code:
    /// ```
    /// # use hex;
    /// use tiauth::error::{ErrorExt, TiauthError};
    ///
    /// fn reply_hex_bytes(hex_string: &str)
    ///     -> Result<Vec<u8>, TiauthError> {
    ///
    ///     let bytes = hex::decode(hex_string)
    ///         .repl("Error decoding hex!")?;
    ///
    ///     Ok(bytes)
    /// }
    /// ```
    fn repl(self, msg: &'static str) -> Result<T, TiauthError> {
        self.map_err(|e| TiauthError {
            error_type: e.error_type(),
            message: msg,
            e: e.to_string()
        })
    }
}

#[derive(Debug)]
pub enum RejectTypes {
    IO,
    Permission,
    AlreadyExists,
    NonExistent,
    DecodeInternal,
    DecodeExternal,
    Tampered,
    Incorrect,
    Internal
}

impl RejectType for RejectTypes {
    fn code(&self) -> u16 {
        match *self {
            RejectTypes::IO => 500,
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

    fn name(&self) -> &'static str {
        match *self {
            RejectTypes::IO => "IO Reject",
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

#[derive(Debug)]
pub struct ErrorReject { pub rt: RejectTypes, pub msg: &'static str, pub e: String }

impl warp::reject::Reject for ErrorReject {}

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

pub(crate) async fn handle_err_reject(err: warp::reject::Rejection) -> Result<impl warp::Reply, warp::Rejection> {
    let code;
    let message: String;
    let error_str: String;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND".to_owned();
        error_str = "".to_string();
        custom_rejection_text(code, message, error_str)
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

        error_str = err_apps;

        //

        custom_rejection_text(code, message, error_str)
    }
    else {
        Err(err)
    }

    //println!("{:?}", err);

    // else {
    //     eprintln!("unhandled rejection: {:?}", err);
    //     code = StatusCode::INTERNAL_SERVER_ERROR;
    //     message = format!("UNHANDLED REJ {:?}", err);
    //     error_str = "".to_string();
    // }
}

pub(crate) async fn handle_reject(err: warp::reject::Rejection) -> Result<impl warp::Reply, std::convert::Infallible> {
    Ok(warp::reply::ReplyRejection::from(err))
}

fn custom_rejection_text(code: StatusCode, message: String, error_str: String) -> Result<impl warp::Reply, warp::Rejection> {
    let error_message = &ErrorMessage {
        code: code.as_u16(),
        message: message.to_owned(),
    };

    let j = warp::reply::json(&error_message);

    debug!("Rejection {}: {}", code, message);
    debug!("Err: {}", error_str);

    Ok(warp::reply::with_status(j, code))
}