use serde::{Deserialize, Serialize};
use validator::{Validate, ValidateArgs};
use lazy_static::lazy_static;
use regex::Regex;
use std::error;
use std::fmt::{Debug, Formatter, Display};

#[derive(Deserialize, Serialize, Validate)]
pub struct UserRegister {
    #[validate(regex="HEX_DASH", length(max=1000))]
    pub user_hex: String,
    #[validate(regex="HEX", length(equal=64))]
    pub password_hash_hex: String,
    #[validate(regex="HEX", length(equal=32))]
    pub salt_hex: String,
}

#[derive(Deserialize, Validate)]
pub struct UserHex {
    #[validate(regex="HEX_DASH", length(max=1000))]
    pub user_hex: String,
}

#[derive(Debug)]
pub struct InputError {
    pub msg: String
}

impl Display for InputError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.msg)
    }
}

impl error::Error for InputError {}

lazy_static! {
    /// Matches Hex Dash representation of a Unicode string
    /// Hex Dash consists of groups of 2-6 hex characters separated by dashes
    /// As such: matches a-f, 0-9 (2-6 chars) followed by a dash zero or more times
    /// And requires another group of a-f, 0-9 (2-6 chars) at the end of the string
    static ref HEX_DASH: Regex = Regex::new(r"^([a-f0-9]{2,6}-)*([a-f0-9]){2,6}$").unwrap();
    /// Matches hexadecimal strings (without '0x' prefix) encoding valid bytes
    /// As such: matches a group of two a-f, 0-9 one or more times
    static ref HEX: Regex = Regex::new(r"^([a-f0-9][a-f0-9])+$").unwrap();
}

/// Takes a struct that implements `ValidateArgs` and validates it, returning a result with an error
/// that contains a prettified version of `ValidationErrors`
pub fn validate<'a, T: ValidateArgs<'a, Args = ()>>(t: &T) -> Result<(), InputError> {
    let res = t.validate_args(());
    res.map_err(|e| {
        let validate_errs = e.field_errors();
        let mut err_strings: Vec<String> = Vec::new();
        for (field_name, err_list) in validate_errs {
            for err in err_list {
                if err.code.clone().into_owned().eq("regex") {
                    err_strings.push(format!("The field {field} has incorrect format.",
                                             field=field_name))
                }
                else {
                    err_strings.push(format!("The field {field} has incorrect {code}.",
                                             field=field_name, code=err.code.clone().into_owned()))
                }
            }
        }
        InputError {
            msg: err_strings.join(" ")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_dash_test_valid() {
        let uu = UserRegister {
            user_hex: "0438f-0243f".to_owned(),
            password_hash_hex: "308a48e47d90ad490de399cda9648017287c8afb6dd2ae7bd0cd07671dc4db60".to_owned(),
            salt_hex: "b90637450812389c17831e80a8c6d1ba".to_owned()
        };
        assert!(uu.validate().is_ok())
    }

    #[test]
    fn hex_dash_test_invalid_hex_dash() {
        let uu = UserRegister {
            user_hex: "0438f-".to_owned(),
            password_hash_hex: "308a48e47d90ad490de399cda96@8017287c8afb6dd2ae7bd0cd07671dc4db60".to_owned(),
            salt_hex: "b90637450812389c17831e80a8c6d1ba".to_owned()
        };
        assert!(uu.validate().is_err())
    }

    #[test]
    fn hex_dash_test_invalid_hex() {
        let uu = UserRegister {
            user_hex: "0438f-0243f".to_owned(),
            password_hash_hex: "308a48e47d90ad490de399cda96@8017287c8afb6dd2ae7bd0cd07!71dc4db60".to_owned(),
            salt_hex: "b90637450812389c17831e80a8c6d1ba".to_owned()
        };
        assert!(uu.validate().is_err())
    }

    #[test]
    fn hex_dash_test_invalid_length() {
        let uu = UserRegister {
            user_hex: "0438f-".to_owned(),
            password_hash_hex: "308a48e47d90ad490de399cda9648017287c8afb6dd2ae7bd0cd07671dc4db60".to_owned(),
            salt_hex: "b90637450812389c17831e80a8c6d1ba".to_owned()
        };
        assert!(uu.validate().is_err())
    }
}