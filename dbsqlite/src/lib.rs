use rusqlite::{params, Connection, Result};
use env_logger::Env;
use log::debug;

#[derive(Debug)]
struct UserAuth {
    user_hex: String,
    password_hash_hex: String,
    salt_hex: String,
    secret_hex: String,
    public_hex: String,
}

#[derive(Debug)]
struct UserClaim {
    origin: String,
    anphd_id: String,
    uuid: String,
    permission: u16,
}

impl UserClaim {
    fn uri(&self) -> String {
        format!("{}--{}", self.origin, self.anphd_id)
    }

    fn claim_id(&self, user_hex: &str) -> String {
        format!("{}---{}", user_hex, self.uri())
    }
}

pub fn run() -> Result<()> {
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "trace")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    log::debug!("main debug");
    log::info!("main info");

    let test_user = UserAuth {
        user_hex: "74-69-70-33fff".to_owned(),
        password_hash_hex: "3bd10a3b40f4950735514b53d7b64a3bb64e29aa299b0135a1c74fd670ce9b11".to_owned(),
        salt_hex: "131f04a35728704974e7b3b2c63022df".to_owned(),
        secret_hex: "735e5879e6c06bceb6371c03a108dea536b4c57c936919944b038f04035852b3".to_owned(),
        public_hex: "f60671a0f894d5ab2257099c0fce183a4e8c586b412e9961f9b53ea50f2031f1".to_owned()
    };

    let mut conn = Connection::open("test")?;
    //create_claim_table(&mut conn)?;
    //create_resources_table(&mut conn)?;
    //create_user_claims_table(&mut conn)?;
    //add_user(&mut conn, test_user)?;
    //originate_resource(&mut conn, "424asdf", "223", "444")?;

    let updated_user = UserAuth {
        user_hex: "424asdffff".to_owned(),
        password_hash_hex: "f60671a0f894d5ab2257099c0fce183a4e8c586b412e9961f9b53ea50f2031f1".to_owned(),
        salt_hex: "131f04a35728704974e7b3b2c63022df".to_owned(),
        secret_hex: "f60671a0f894d5ab2257099c0fce183a4e8c586b412e9961f9b53ea50f2031f1".to_owned(),
        public_hex: "f60671a0f894d5ab2257099c0fce183a4e8c586b412e9961f9b53ea50f2031f1".to_owned()
    };
    //upsert_claim(&mut conn, "74-69-70", test_claim)?;
    //update_user_auth(&mut conn, updated_user)?;
    let user = read_user_auth(&mut conn, "424asdf", true);
    match user {
        Ok(u) => println!("{}", u.password_hash_hex),
        Err(e) => println!("{:?}", e)
    }

    let user_claims = read_user_claims(&mut conn, "424asdf")?;
    for claim in user_claims {
        println!("{:?}", claim);
    }

    Ok(())
}

static AUTH_TABLE: &'static str = "user_auth";

static USER_HEX: &'static str = "user_hex";
static PASSWORD_HASH_HEX: &'static str = "password_hash_hex";
static SALT_HEX: &'static str = "salt_hex";
static SECRET_HEX: &'static str = "secret_hex";
static PUBLIC_HEX: &'static str = "public_hex";

fn create_auth_table(conn: &mut Connection) -> Result<()> {
    let sql_string = format!("\
        CREATE TABLE {} (
        {1} TEXT PRIMARY KEY CHECK(LENGTH({1}) < 1000),
        {2} TEXT CHECK({2} NOT NULL and LENGTH({2}) == 64),
        {3} TEXT CHECK({3} NOT NULL and LENGTH({3}) == 32),
        {4} TEXT CHECK({4} NOT NULL and LENGTH({4}) == 64),
        {5} TEXT CHECK({5} NOT NULL and LENGTH({5}) == 64)
            )",
        AUTH_TABLE, USER_HEX, PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);

    let tx = conn.transaction()?;
    match tx.execute(&sql_string, [])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

static CLAIM_ID: &'static str = "claim_id";
static CLAIMS_TABLE: &'static str = "user_claims";
static RESOURCE_URI: &'static str = "uri";
static RESOURCE_UUID: &'static str = "uuid";
static CLAIM_PERMISSION: &'static str = "permission";

fn create_user_claims_table(conn: &mut Connection) -> Result<()> {
    let sql_table_string = format!("\
        CREATE TABLE {table} (
        {uh_name} TEXT NOT NULL,
        {claim_id} TEXT PRIMARY KEY CHECK({claim_id} = {uh_name} || '---' || {uri}),
        {uri} TEXT NOT NULL,
        {uuid} TEXT NOT NULL,
        {permission} INTEGER NOT NULL,
        FOREIGN KEY({uri}) REFERENCES {resources_table}({uri}),
        FOREIGN KEY({uh_name}) REFERENCES {auth_table}({uh_name})
            )",
        table=CLAIMS_TABLE, uh_name=USER_HEX, claim_id=CLAIM_ID, uri=RESOURCE_URI, uuid=RESOURCE_UUID,
        permission=CLAIM_PERMISSION, resources_table=RESOURCES_TABLE, auth_table=AUTH_TABLE);

    let sql_index_string = format!("
        CREATE INDEX {uh_name}_index
        ON {table}({uh_name})",
        uh_name=USER_HEX, table=CLAIMS_TABLE);

    let tx = conn.transaction()?;
    match tx.execute(&sql_table_string, [])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            Ok(updated)
        },
        Err(err) => Err(err),
    }?;

    match tx.execute(&sql_index_string, [])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

static RESOURCES_TABLE: &'static str = "user_resources";
static RESOURCE_ORIGIN: &'static str = "origin";
static RESOURCE_ANPHD_ID: &'static str = "anphd_id";

fn create_resources_table(conn: &mut Connection) -> Result<()> {
    let sql_string = format!("\
        CREATE TABLE {table} (
        {uri} TEXT PRIMARY KEY CHECK({uri} = {origin} || '--' || {anphd_id}),
        {origin} TEXT NOT NULL,
        {anphd_id} TEXT NOT NULL
            )", table=RESOURCES_TABLE, uri=RESOURCE_URI, origin=RESOURCE_ORIGIN, anphd_id=RESOURCE_ANPHD_ID);

    let tx = conn.transaction()?;
    match tx.execute(&sql_string, [])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

fn add_user(conn: &mut Connection, user: UserAuth) -> Result<()> {
    let sql_str_auth = format!("\
        INSERT INTO {} ({}, {}, {}, {}, {})
        VALUES(?1, ?2, ?3, ?4, ?5)",
        AUTH_TABLE, USER_HEX, PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);
    debug!("add user:\n{}", sql_str_auth);

    let tx = conn.transaction()?;
    match tx.execute(&sql_str_auth, params![
            user.user_hex,
            user.password_hash_hex,
            user.salt_hex,
            user.secret_hex,
            user.public_hex,
        ])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

fn originate_resource(conn: &mut Connection, origin_user_hex: &str, resource_anphd_id: &str,
                      resource_uuid: &str) -> Result<()> {
    let sql_str_resource = format!("\
        INSERT INTO {table} ({uri}, {origin}, {anphd_id})
        VALUES(?1, ?2, ?3)",
        table=RESOURCES_TABLE, uri=RESOURCE_URI, origin=RESOURCE_ORIGIN, anphd_id=RESOURCE_ANPHD_ID);
    debug!("originate resource:\n{}", sql_str_resource);

    let sql_str_claim = format!("\
        INSERT INTO {table} ({claim_id}, {user_hex}, {uri}, {uuid}, {permission})
        VALUES(?1, ?2, ?3, ?4, ?5)",
        table=CLAIMS_TABLE, claim_id=CLAIM_ID, user_hex=USER_HEX, uri=RESOURCE_URI,
                                   uuid=RESOURCE_UUID, permission=CLAIM_PERMISSION);
    debug!("originate resource claim:\n{}", sql_str_resource);

    let uri = format!("{}--{}", origin_user_hex, resource_anphd_id);
    let claim_id = format!("{}---{}", origin_user_hex, uri);
    let tx = conn.transaction()?;
    match tx.execute(&sql_str_resource, params![
            uri,
            origin_user_hex,
            resource_anphd_id,
        ])
    {
        Ok(updated) => {
            debug!("originated resource: {} rows were updated", updated);
            Ok(updated)
        },
        Err(err) => Err(err),
    }?;
    match tx.execute(&sql_str_claim, params![
            claim_id,
            origin_user_hex,
            uri,
            resource_uuid,
            0
        ])
    {
        Ok(updated) => {
            debug!("originated resource claim: {} rows were updated. committing.", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

fn upsert_claim(conn: &mut Connection, user_hex: &str, user_claim: UserClaim) -> Result<()> {
    let sql_str_claim = format!("\
        INSERT INTO {table} ({claim_id}, {user_hex}, {uri}, {uuid}, {permission})
        VALUES(?1, ?2, ?3, ?4, ?5)
        ON CONFLICT({claim_id}) DO UPDATE SET
        {claim_id}=?1, {user_hex}=?2, {uri}=?3, {uuid}=?4, {permission}=?5",
        table=CLAIMS_TABLE, claim_id=CLAIM_ID, user_hex=USER_HEX, uri=RESOURCE_URI,
                                uuid=RESOURCE_UUID, permission=CLAIM_PERMISSION);
    debug!("upsert claim:\n{}", sql_str_claim);
    let tx = conn.transaction()?;
    match tx.execute(&sql_str_claim, params![
            user_claim.claim_id(user_hex),
            user_hex,
            user_claim.uri(),
            user_claim.uuid,
            user_claim.permission
        ])
    {
        Ok(updated) => {
            debug!("originated resource claim: {} rows were updated. committing.", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

fn update_user_auth(conn: &mut Connection, user: UserAuth) -> Result<()> {
    let mut columns: Vec<String> = Vec::new();

    if !user.password_hash_hex.is_empty() {
        columns.push(format!("{}='{}'", PASSWORD_HASH_HEX, user.password_hash_hex));
    }
    if !user.salt_hex.is_empty() {
        columns.push(format!("{}='{}'", SALT_HEX, user.salt_hex));
    }
    if !user.secret_hex.is_empty() {
        columns.push(format!("{}='{}'", SECRET_HEX, user.secret_hex));
    }
    if !user.public_hex.is_empty() {
        columns.push(format!("{}='{}'", PUBLIC_HEX, user.public_hex));
    }
    let columns = columns.join(",");

    let sql_str = format!("UPDATE {table} SET {columns} WHERE {uh_name} = '{uh}'",
                          table=AUTH_TABLE, columns=columns, uh_name=USER_HEX, uh=user.user_hex);
    debug!("update user:\n{}", sql_str);
    let tx = conn.transaction()?;
    match tx.execute(&sql_str, [])
    {
        Ok(updated) => {
            debug!("{} rows were updated", updated);
            tx.commit()
        },
        Err(err) => Err(err),
    }
}

fn read_user_auth(conn: &mut Connection, user_hex: &str, secret: bool) -> Result<UserAuth> {
    let columns: String;
    if !secret {
        columns = format!("{}, {}", SALT_HEX, PUBLIC_HEX);
    } else {
        columns = format!("{}, {}, {}, {}", PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);
    }
    let sql_string = format!("SELECT DISTINCT {columns} FROM {table} WHERE {uh_name}='{uh}'",
                             columns=columns, table=AUTH_TABLE, uh_name=USER_HEX, uh=user_hex);
    let user = conn.query_row(&sql_string, [], |row| {
        Ok(UserAuth {
            user_hex: user_hex.to_owned(),
            password_hash_hex: if secret { row.get(0)? } else { "".to_owned() },
            salt_hex: if !secret { row.get(0)? } else { row.get(1)? },
            secret_hex: if secret { row.get(2)? } else { "".to_owned() },
            public_hex: if !secret { row.get(1)? } else { row.get(3)? },
        })
    })?;

    Ok(user)
}

fn read_user_claims(conn: &mut Connection, user_hex: &str) -> Result<Vec<UserClaim>> {
    let columns= format!("{}, {}, {}", RESOURCE_URI, RESOURCE_UUID, CLAIM_PERMISSION);
    let sql_string = format!("SELECT {columns} FROM {table} WHERE {uh_name}='{uh}'",
                             columns=columns, table=CLAIMS_TABLE, uh_name=USER_HEX, uh=user_hex);
    let mut stmt = conn.prepare(&sql_string)?;

    let user_claims = stmt.query_map([], |row| {
        let uri: String = row.get(0)?;
        let uri = uri.split("--").collect::<Vec<&str>>();
        let origin = *uri.get(0).unwrap();
        let anphd_id = *uri.get(1).unwrap();
        Ok(UserClaim {
            origin: origin.to_owned(),
            anphd_id: anphd_id.to_owned(),
            uuid: row.get(1)?,
            permission: row.get(2)?
        })
    })?.filter_map(|claim| claim.ok()).collect::<Vec<UserClaim>>();

    Ok(user_claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_auth_table_test() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_auth_table(&mut conn).unwrap();
        let sql_string = format!("INSERT INTO {} ({}, {}, {}, {}, {}) VALUES(?1, ?2, ?3, ?4, ?5)",
                                 AUTH_TABLE, USER_HEX, PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);
        let mock_user = UserAuth {
            user_hex: "74-74".to_owned(),
            password_hash_hex: "54d8b194ea913a028063c3b19a7124d3dded561b1b18c760b1492a6ba717004e".to_owned(),
            salt_hex: "07b7ccb11df7581a6c06f5e2bcc85858".to_owned(),
            secret_hex: "4babbac197aebb1c87f6edb2c7a4712f65550d4f1a304dd0233b4bac834a52c0".to_owned(),
            public_hex: "7f87e14e08f036c0d3ca6f18787907b5193c2d9aadb3a93f9b39408fd2cbf5f6".to_owned(),
        };

        let res = conn.execute(&sql_string, params![
            mock_user.user_hex,
            mock_user.password_hash_hex,
            mock_user.salt_hex,
            mock_user.secret_hex,
            mock_user.public_hex,
        ]);
        assert_eq!(res.unwrap(), 1);
        let columns = format!("{}, {}, {}, {}, {}", USER_HEX, PASSWORD_HASH_HEX, SALT_HEX, SECRET_HEX, PUBLIC_HEX);
        let user_hex = "74-74";
        let sql_string = format!("SELECT DISTINCT {columns} FROM {table} WHERE {uh_name}='{uh}'",
                                 columns=columns, table=AUTH_TABLE, uh_name=USER_HEX, uh=user_hex);
        let user = conn.query_row(&sql_string, [], |row| {
            Ok(UserAuth {
                user_hex: row.get(0).unwrap(),
                password_hash_hex: row.get(1).unwrap(),
                salt_hex: row.get(2).unwrap(),
                secret_hex: row.get(3).unwrap(),
                public_hex: row.get(4).unwrap(),
            })
        }).unwrap();
        assert_eq!(user.user_hex, mock_user.user_hex);
        assert_eq!(user.public_hex, mock_user.public_hex);
    }
}
