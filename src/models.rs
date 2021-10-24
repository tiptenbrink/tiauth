use crate::schema::user_auth;

#[derive(Queryable, Debug)]
pub struct UserAuth {
    pub user_hex: String,
    pub password_hash_hex: String,
    pub salt_hex: String,
    pub secret_hex: String,
    pub public_hex: String,
}