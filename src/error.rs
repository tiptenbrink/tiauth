pub trait RejectType {
    fn code(&self) -> u16;

    fn name(&self) -> &'static str;
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