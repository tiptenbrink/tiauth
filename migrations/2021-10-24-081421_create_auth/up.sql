-- Your SQL goes here
CREATE TABLE user_auth (
    user_hex TEXT PRIMARY KEY NOT NULL CHECK(LENGTH(user_hex) < 1000),
    password_hash_hex TEXT NOT NULL CHECK(LENGTH(password_hash_hex) == 64),
    salt_hex TEXT NOT NULL CHECK(LENGTH(salt_hex) == 32),
    secret_hex TEXT NOT NULL CHECK(LENGTH(secret_hex) == 64),
    public_hex TEXT NOT NULL CHECK(LENGTH(public_hex) == 64)
    )