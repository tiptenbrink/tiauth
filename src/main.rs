#![allow(dead_code, unused_imports)]

use redb::{Database, Error, ReadableTable, TableDefinition, TypeName, Value};
use opaque_borink::server::{register_server, register_server_finish, login_server, login_server_finish};
use opaque_borink::{create_setup, Error as OpaqueError};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::{fs::read, str};
use std::fmt::Debug;
use serde::{Deserialize, Serialize};
use rmp_serde::{decode, encode};
use std::cell::OnceCell;
use terrors::OneOf;
use base64::{engine::general_purpose as b64, Engine as _};
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, SeedableRng};

mod crypto;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Login {
    user_id: String,
    password_file: String,
    #[serde(with = "serde_bytes")]
    claims: Vec<u8>
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Session {
    user_id: String,
    expires: i128,
    /// These are a subset of the "login claims"
    #[serde(with = "serde_bytes")]
    session_claims: Vec<u8>
}

const SERVER: TableDefinition<&str, String> = TableDefinition::new("server");

fn session_table<'a>(state: &'a mut State, application: &str) -> TableDefinition<'a, &'static str, &'static [u8]> {
    let tables = &mut state.tables;
    
    let table_name = tables.entry(format!("{}:sessions", application)).or_insert_with(|| format!("{}:sessions", application));

    TableDefinition::new(table_name)
}

fn user_table<'a>(tables: &'a mut HashMap<String, String>, application: &str) -> TableDefinition<'a, &'static str, &'static [u8]> {
    let table_name = tables.entry(format!("{}:users", application)).or_insert_with(|| format!("{}:users", application));

    TableDefinition::new(table_name)
}

fn state_table<'a>(tables: &'a mut HashMap<String, String>, application: &str) -> TableDefinition<'a, &'static str, &'static str> {
    let table_name = tables.entry(format!("{}:state", application)).or_insert_with(|| format!("{}:state", application));
    TableDefinition::new(table_name)
}

fn open_db() -> Result<Database, Error> {
    Ok(Database::create("my_db.redb")?)
}

fn set_login(state: &mut State, login: &Login, application: &str) -> Result<(), Error> {
    let buf = encode::to_vec_named(login).unwrap();
    let user_id = login.user_id.as_str();
    let table_def = user_table(&mut state.tables, application);
    let write_txn = state.db.begin_write()?;
    
    {
        let mut table = write_txn.open_table(table_def)?;
        table.insert(user_id, buf.as_slice())?;
    }
    write_txn.commit()?;

    Ok(())
}

fn set_login_field(state: &mut State, application: &str, user_id: &str, password_file: String) -> Result<(), Error> {
    let table_def = user_table(&mut state.tables, application);
    let write_txn = state.db.begin_write()?;
    {
        let mut table = write_txn.open_table(table_def)?;
        let mut login: Login = decode::from_read(table.get(user_id)?.unwrap().value()).unwrap();
        login.password_file = password_file;

        let buf = encode::to_vec_named(&login).unwrap();
        table.insert(user_id, buf.as_slice())?;
    };
    
    write_txn.commit()?;

    Ok(())
}

fn get_login(state: &mut State, application: &str, user_id: &str) -> Result<Login, Error> {
    let read_txn = state.db.begin_read()?;
    let table_def = user_table(&mut state.tables, application);

    let table = read_txn.open_table(table_def)?;

    Ok(decode::from_read(table.get(user_id)?.unwrap().value()).unwrap())
}

fn set_setup(db: &Database) -> Result<(), Error> {
    let write_txn = db.begin_write()?;

    let setup = {
        let mut table = write_txn.open_table(SERVER)?;
        let setup = table.get("opaque_setup")?.map(|a| a.value());

        if let Some(setup) = setup {
            setup
        } else {
            let setup = create_setup();
            table.insert("opaque_setup", setup.clone())?;
            setup
        }
    };
    
    write_txn.commit()?;

    let _ = SETUP.get_or_init(|| setup);

    Ok(())
}

fn start_register(request: &str, user_id: &str) -> Result<String, OpaqueError> {
    let setup = SETUP.get().unwrap();

    register_server(setup, request, user_id)
}

trait WrapErrorOneOf<T, E, Target> {
    fn to_one_of(self) -> Result<T, OneOf<(Target,)>>;

    fn to_one_of_two<O>(self) -> Result<T, OneOf<(Target,O,)>>;

    fn to_one_of_twond<O>(self) -> Result<T, OneOf<(O,Target,)>>;
}

impl<T, E, Target> WrapErrorOneOf<T, E, Target> for Result<T, E>
where
    E: Into<Target> + Send + Sync + 'static,
    Target: Send + Sync + 'static
{
    fn to_one_of(self) -> Result<T, OneOf<(Target,)>> {
        self.map_err(|e| { e.into() }).map_err(OneOf::from)
    }

    fn to_one_of_two<O>(self) -> Result<T, OneOf<(Target,O,)>> {
        let as_one_of = self.to_one_of();
        as_one_of.map_err(OneOf::broaden)
    }

    fn to_one_of_twond<O>(self) -> Result<T, OneOf<(O,Target,)>> {
        let as_one_of = self.to_one_of();
        as_one_of.map_err(OneOf::broaden)
    }
}

fn nonce_384(state: &mut State) -> String {
    let mut data = vec![0u8; 48];

    state.rng.fill(data.as_mut_slice());

    b64::URL_SAFE_NO_PAD.encode(data.as_mut_slice())
}

fn register_finish(state: &mut State, application: &str, request: &str, user_id: &str) -> Result<(), OneOf<(Error, OpaqueError)>> {
    let password_file = register_server_finish(request)
        .to_one_of_twond()?;

    set_login_field(state, application, user_id, password_file)
        .to_one_of_two()?;

    Ok(())
}

fn write_state(state: &mut State, application: &str, key: &str, state_data: &str) -> Result<(), Error> {
    let table_def = state_table(&mut state.tables, application);
    
    let write_txn = state.db.begin_write()?;
    {
        let mut table = write_txn.open_table(table_def)?;
        table.insert(key, state_data)?;
    }
    write_txn.commit()?;

    Ok(())
}

fn read_state(state: &mut State, application: &str, key: &str) -> Result<String, Error> {
    let table_def = state_table(&mut state.tables, application);
    let write_txn = state.db.begin_write()?;
    let state_data = {
        let mut table = write_txn.open_table(table_def)?;
        let accesss = table.remove(key)?.unwrap();
        let value = accesss.value();
        value.to_owned()
    };
    write_txn.commit()?;

    Ok(state_data)
}

fn login_start(state: &mut State, application: &str, user_id: &str, request: &str) -> Result<(String, String), OneOf<(Error, OpaqueError)>> {
    let setup = SETUP.get().unwrap();

    let read_login = get_login(state, application, user_id).unwrap();
    
    let (response, state_data) = login_server(setup, &read_login.password_file, request, user_id)
        .to_one_of_twond()?;

    let nonce = nonce_384(state);
    let key = format!("{}:{}", user_id, nonce);

    write_state(state, application, &key, &state_data)
        .to_one_of_two()?;

    Ok((response, nonce))
}

fn login_finish(state: &mut State, application: &str, user_id: &str, request: &str, nonce: &str) -> Result<String, OneOf<(Error, OpaqueError)>> {
    // 384 bits nonce, i.e. 48 bytes, 64 base64url characters, which are all 1 byte, so 64 bytes
    assert_eq!(nonce.len(), 64);

    let key = format!("{}:{}", user_id, nonce);

    let state = read_state(state, application, &key)
        .to_one_of_two()?;

    let secret = login_server_finish(request, &state)
        .to_one_of_twond()?;

    Ok(secret)
}

static SETUP: OnceLock<String> = OnceLock::new();

struct State<'a, 'b, 'c> {
    tables: &'b mut HashMap<String, String>,
    db: &'a Database,
    rng: &'c mut StdRng
}

fn main() {
    let db = open_db().unwrap();

    set_setup(&db).unwrap();

    let mut map = HashMap::new();
    let mut seed = [0u8; 32];
    OsRng.fill(&mut seed);
    let mut rng = StdRng::from_seed(seed);
    
    let mut state = State {
        tables: &mut map,
        db: &db,
        rng: &mut rng
    };

    let value = Login {
        user_id: "hi".to_owned(),
        password_file: "pw".to_owned(),
        claims: Vec::new()
    };

    let app = "abc".to_owned();

    set_login(&mut state, &value, &app).unwrap();

    let read_login = get_login(&mut state, &app, &value.user_id).unwrap();
}


#[cfg(test)]
mod tests {
    use super::*;
    use opaque_borink::client::{client_register, client_register_finish, client_login, client_login_finish};

    fn setup() -> (Database, StdRng) {
        let tmp: tempfile::NamedTempFile = tempfile::NamedTempFile::new().unwrap();
        let db = Database::create(tmp.path()).unwrap();
        let setup = create_setup();
        let _ = SETUP.get_or_init(|| setup);

        let mut seed = [0u8; 32];
        OsRng.fill(&mut seed);
        let rng = StdRng::from_seed(seed);

        (db, rng)
    }

    #[test]
    fn login_set_read() {
        let (db, mut rng) = setup();
        let mut map = HashMap::new();
        let mut state = State {
            tables: &mut map,
            db: &db,
            rng: &mut rng
        };

        let value = Login {
            user_id: "hi".to_owned(),
            password_file: "pw".to_owned(),
            claims: Vec::new()
        };

        let app = "abc".to_owned();

        set_login(&mut state, &value, &app).unwrap();

        let read_login = get_login(&mut state, &app, &value.user_id).unwrap();

        assert_eq!(value.user_id, read_login.user_id);
        assert_eq!(value.password_file, read_login.password_file);
        assert_eq!(value.claims, read_login.claims);
    }

    fn create_user(state: &mut State, user_id: &str, application: &str, password: &str) {
        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims: Vec::new()
        };

        set_login(state, &value, &application).unwrap();

        let (request, client_state) = client_register(password).unwrap();
        let server_response = start_register(&request, user_id).unwrap();
        let request = client_register_finish(&client_state, password, &server_response).unwrap();
        register_finish(state, &application, &request, user_id).unwrap();
    }

    #[test]
    fn register() {
        let (db, mut rng) = setup();
        let mut map = HashMap::new();
        let mut state = State {
            tables: &mut map,
            db: &db,
            rng: &mut rng
        };

        let user_id = "hi";

        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims: Vec::new()
        };
        let app = "abc";
        let password = "pass";

        create_user(&mut state, user_id, app, password);

        let read_login = get_login(&mut state, &app, &value.user_id).unwrap();

        assert_ne!(value.password_file, read_login.password_file)
    }

    #[test]
    fn login() {
        let (db, mut rng) = setup();
        let mut map = HashMap::new();
        let mut state = State {
            tables: &mut map,
            db: &db,
            rng: &mut rng
        };

        let user_id = "hi";
        let app = "abc";
        let password = "pass";

        create_user(&mut state, user_id, app, password);

        let (request, client_state) = client_login(password).unwrap();

        let (response, nonce) = login_start(&mut state, app, user_id, &request).unwrap();

        let (request, secret) = client_login_finish(&client_state, password, &response).unwrap();

        let secret_server = login_finish(&mut state, app, user_id, &request, &nonce).unwrap();

        assert_eq!(secret, secret_server)
    }
}