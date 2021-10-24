use diesel::table;

table! {
    user_auth (user_hex) {
        user_hex -> Text,
        password_hash_hex -> Text,
        salt_hex -> Text,
        secret_hex -> Text,
        public_hex -> Text,
    }
}
