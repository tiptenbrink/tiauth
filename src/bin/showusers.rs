use diesel::prelude::*;

use tiauth::db;
use tiauth::schema::user_auth::dsl::user_auth;
use tiauth::models::UserAuth;

#[tokio::main]
async fn main() {
    let connection = db::connect().await;
    let all_users: Vec<UserAuth> = user_auth.load::<UserAuth>(&connection).unwrap();
    println!("{:?}", all_users)
}