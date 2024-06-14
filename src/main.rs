use redb::{Database, Error, ReadableTable, TableDefinition, TypeName, Value};
use opaque_borink::server::{register_server, register_server_finish};
use opaque_borink::{create_setup, Error as OpaqueError};
use std::sync::OnceLock;
use std::{fs::read, str};
use std::fmt::Debug;
use serde::{Deserialize, Serialize};
use rmp_serde::{decode, encode};
use std::cell::OnceCell;
use terrors::OneOf;

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

const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("sessions");
const SERVER: TableDefinition<&str, String> = TableDefinition::new("server");

fn open_db() -> Result<Database, Error> {
    Ok(Database::create("my_db.redb")?)
}

fn set_login(db: &Database, login: &Login) -> Result<(), Error> {
    let buf = encode::to_vec_named(login).unwrap();
    let user_id = login.user_id.as_str();
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(USERS)?;
        table.insert(user_id, buf.as_slice())?;
    }
    write_txn.commit()?;

    Ok(())
}

fn get_login(db: &Database, user_id: &str) -> Result<Login, Error> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(USERS)?;

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



fn register_finish(db: &Database, request: &str) -> Result<(), OneOf<(Error, OpaqueError)>> {
    let password_file = register_server_finish(request)
        .to_one_of_twond()?;


    let write_txn = db.begin_write()
        .to_one_of_two()?;


    Ok(())
}

static SETUP: OnceLock<String> = OnceLock::new();

fn main() {
    let db = open_db().unwrap();

    set_setup(&db).unwrap();

    let value = Login {
        user_id: "hi".to_owned(),
        password_file: "pw".to_owned(),
        claims: Vec::new()
    };

    set_login(&db, &value).unwrap();

    let read_login = get_login(&db, &value.user_id).unwrap();

    println!("{:?}", read_login);
}