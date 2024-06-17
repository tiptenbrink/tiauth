#![allow(dead_code)]

use base64::{engine::general_purpose as b64, Engine as _};
use crypto::{
    create_key, create_session_key, load_key, load_public_key, load_session_key, save_key,
    save_session_key, verify_signature, Key, PublicKey, SessionKey,
};
use opaque_borink::server::{
    login_server, login_server_finish, register_server, register_server_finish,
};
use opaque_borink::{create_setup, Error as OpaqueError};
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, SeedableRng};
use redb::{Database, Error, ReadableTable, TableDefinition, WriteTransaction};
use rmp_serde::{decode, encode};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::str;
use std::time::SystemTime;
use terrors::OneOf;

mod crypto;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Login {
    user_id: String,
    password_file: String,
    claims: Value,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Session {
    user_id: String,
    expires: u64,
    /// These are a subset of the "login claims"
    /// They are a msgpack map
    session_claims: Value,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct SignedSession {
    #[serde(with = "serde_bytes")]
    session_encoded: Vec<u8>,

    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

/// Persistent server data, such as OPAQUE private key
const SERVER: TableDefinition<&str, String> = TableDefinition::new("server");

/// App identities
const APPS: TableDefinition<&str, &[u8]> = TableDefinition::new("apps");

#[derive(Debug, PartialEq, Deserialize, Serialize)]
enum ProofUse {
    // String is user_id
    ResetPassword(String),

    CreateUser(String),
}

impl ProofUse {
    fn proof_repr(&self) -> String {
        match self {
            Self::ResetPassword(user_id) => format!("{}:reset_password", user_id).to_string(),
            Self::CreateUser(user_id) => format!("{}:create_user", user_id).to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Proof {
    /// Nonce ensures it is used just once
    nonce: String,
    expires: u64,
    application: String,
    proof_use: ProofUse,
    // This signature is base64url-encoded.
    signature: String,
}

fn proof_data(application: &str, nonce: &str, expires: u64, proof_use: &ProofUse) -> Vec<u8> {
    format!(
        "{}.{}.{}.{}",
        application,
        nonce,
        expires,
        proof_use.proof_repr()
    )
    .into_bytes()
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Application {
    // This must be a
    public_key: String,
    name: String,
}

// TODO maybe move this to start? I don't like that the DB stuff can be called at any moment
fn app_key<'a>(state: &'a mut State, app_name: &str) -> Result<&'a PublicKey, Error> {
    let key = state.app_keys.get(app_name);

    if key.is_some() {
        // This is necessary due to borrow checker limitation (see https://blog.rust-lang.org/2022/08/05/nll-by-default.html)
        // It requires the "borrow checker of the future"
        // Alternative is to instead return an owned PublicKey. Probably a clone is faster than a second get, but it doesn't matter much
        // Entry API is also not an option because the below code is fallible
        Ok(state.app_keys.get(app_name).unwrap())
    } else {
        let read_txn = state.db.begin_read()?;

        let table = read_txn.open_table(APPS)?;

        let application: Application =
            decode::from_read(table.get(app_name)?.unwrap().value()).unwrap();

        let public_key = load_public_key(&application.public_key);

        state
            .app_keys
            .insert(app_name.to_owned(), public_key.clone());

        Ok(state.app_keys.get(app_name).unwrap())
    }
}

fn session_table<'a>(
    state: &'a mut State,
    application: &str,
) -> TableDefinition<'a, &'static str, &'static [u8]> {
    let tables = &mut state.tables;

    let table_name = tables
        .entry(format!("{}:sessions", application))
        .or_insert_with(|| format!("{}:sessions", application));

    TableDefinition::new(table_name)
}

fn user_table<'a>(
    tables: &'a mut HashMap<String, String>,
    application: &str,
) -> TableDefinition<'a, &'static str, &'static [u8]> {
    let table_name = tables
        .entry(format!("{}:users", application))
        .or_insert_with(|| format!("{}:users", application));

    TableDefinition::new(table_name)
}

fn state_table<'a>(
    tables: &'a mut HashMap<String, String>,
    application: &str,
) -> TableDefinition<'a, &'static str, &'static str> {
    let table_name = tables
        .entry(format!("{}:state", application))
        .or_insert_with(|| format!("{}:state", application));
    TableDefinition::new(table_name)
}

fn open_db() -> Result<Database, Error> {
    Ok(Database::create("my_db.redb")?)
}

fn set_login(state: &mut State, login: &Login, application: &str) -> Result<(), Error> {
    let buf = encode::to_vec_named(login).unwrap();
    let user_id = login.user_id.as_str();
    let table_def = user_table(state.tables, application);
    let write_txn = state.db.begin_write()?;

    {
        let mut table = write_txn.open_table(table_def)?;
        table.insert(user_id, buf.as_slice())?;
    }
    write_txn.commit()?;

    Ok(())
}

/// Assumes a user has already been created. If `require_unset_password` is set to false, it will change it even if the password file is non-empty.
/// Returns true if password was written.
fn set_login_field(
    state: &mut State,
    application: &str,
    user_id: &str,
    password_file: String,
    require_unset_password: bool,
) -> Result<bool, Error> {
    let write_txn = state.db.begin_write()?;

    let result = set_login_field_write(
        &write_txn,
        state,
        application,
        user_id,
        password_file,
        require_unset_password,
    )?;

    write_txn.commit()?;

    Ok(result)
}

/// Assumes a user has already been created. If `require_unset_password` is set to false, it will change it even if the password file is non-empty.
/// Returns true if password was written.
fn set_login_field_write(
    write_txn: &WriteTransaction,
    state: &mut State,
    application: &str,
    user_id: &str,
    password_file: String,
    require_unset_password: bool,
) -> Result<bool, Error> {
    let table_def = user_table(state.tables, application);
    let mut table = write_txn.open_table(table_def)?;
    let mut login: Login = decode::from_read(table.get(user_id)?.unwrap().value()).unwrap();

    if require_unset_password && !login.password_file.is_empty() {
        return Ok(false);
    }

    login.password_file = password_file;

    let buf = encode::to_vec_named(&login).unwrap();
    table.insert(user_id, buf.as_slice())?;

    Ok(true)
}

fn get_login(state: &mut State, application: &str, user_id: &str) -> Result<Login, Error> {
    let read_txn = state.db.begin_read()?;
    let table_def = user_table(state.tables, application);

    let table = read_txn.open_table(table_def)?;

    Ok(decode::from_read(table.get(user_id)?.unwrap().value()).unwrap())
}

fn init_private_state(db: &Database, rng: &mut StdRng) -> Result<PrivateState, Error> {
    let write_txn = db.begin_write()?;

    let (opaque, session, private) = {
        let mut table = write_txn.open_table(SERVER)?;
        let setup = table.get("opaque_setup")?.map(|a| a.value());

        let setup = if let Some(setup) = setup {
            setup
        } else {
            let setup = create_setup();
            table.insert("opaque_setup", setup.clone())?;
            setup
        };

        let session_key = table.get("session_key")?.map(|a| a.value());

        let session_key = if let Some(session_key) = session_key {
            load_session_key(&session_key)
        } else {
            let session_key = create_session_key(rng);
            let saved_session_key = save_session_key(&session_key);

            table.insert("private_key", saved_session_key.session)?;
            session_key
        };

        let private_key = table.get("private_key")?.map(|a| a.value());

        let keypair = if let Some(private_key) = private_key {
            load_key(&private_key)
        } else {
            let keypair = create_key();
            let saved_private_key = save_key(&keypair);

            table.insert("private_key", saved_private_key.private)?;
            keypair
        };

        (setup, session_key, keypair)
    };
    write_txn.commit()?;

    Ok(PrivateState {
        opaque,
        session,
        private,
    })
}

fn register_application(state: &mut State, application: Application) -> Result<(), Error> {
    let app_buf = encode::to_vec_named(&application).unwrap();

    let write_txn = state.db.begin_write()?;
    {
        let mut table = write_txn.open_table(APPS)?;
        table
            .insert(application.name.as_str(), app_buf.as_slice())
            .unwrap();
    }
    write_txn.commit()?;

    Ok(())
}

fn start_register(state: &State, request: &str, user_id: &str) -> Result<String, OpaqueError> {
    register_server(&state.private.opaque, request, user_id)
}

trait WrapErrorOneOf<T, E, Target> {
    fn to_one_of(self) -> Result<T, OneOf<(Target,)>>;

    fn to_one_of_two<O>(self) -> Result<T, OneOf<(Target, O)>>;

    fn to_one_of_twond<O>(self) -> Result<T, OneOf<(O, Target)>>;
}

impl<T, E, Target> WrapErrorOneOf<T, E, Target> for Result<T, E>
where
    E: Into<Target> + Send + Sync + 'static,
    Target: Send + Sync + 'static,
{
    fn to_one_of(self) -> Result<T, OneOf<(Target,)>> {
        self.map_err(|e| e.into()).map_err(OneOf::from)
    }

    fn to_one_of_two<O>(self) -> Result<T, OneOf<(Target, O)>> {
        let as_one_of = self.to_one_of();
        as_one_of.map_err(OneOf::broaden)
    }

    fn to_one_of_twond<O>(self) -> Result<T, OneOf<(O, Target)>> {
        let as_one_of = self.to_one_of();
        as_one_of.map_err(OneOf::broaden)
    }
}

fn nonce_384(state: &mut State) -> String {
    let mut data = vec![0u8; 48];

    state.rng.fill(data.as_mut_slice());

    b64::URL_SAFE_NO_PAD.encode(data.as_mut_slice())
}

fn register_finish(
    state: &mut State,
    application: &str,
    request: &str,
    user_id: &str,
    require_unset_password: bool,
) -> Result<(), OneOf<(Error, OpaqueError)>> {
    let password_file = register_server_finish(request).to_one_of_twond()?;

    set_login_field(
        state,
        application,
        user_id,
        password_file,
        require_unset_password,
    )
    .to_one_of_two()?;

    Ok(())
}

fn write_state(
    state: &mut State,
    application: &str,
    key: &str,
    state_data: &str,
) -> Result<(), Error> {
    let table_def = state_table(state.tables, application);

    let write_txn = state.db.begin_write()?;
    {
        let mut table = write_txn.open_table(table_def)?;
        table.insert(key, state_data)?;
    }
    write_txn.commit()?;

    Ok(())
}

fn read_state(state: &mut State, application: &str, key: &str) -> Result<String, Error> {
    let table_def = state_table(state.tables, application);
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

// TODO implement fake credential, also if password file is empty
fn login_start(
    state: &mut State,
    application: &str,
    user_id: &str,
    request: &str,
) -> Result<(String, String), OneOf<(Error, OpaqueError)>> {
    let read_login = get_login(state, application, user_id).unwrap();

    let (response, state_data) = login_server(
        &state.private.opaque,
        &read_login.password_file,
        request,
        user_id,
    )
    .to_one_of_twond()?;

    let nonce = nonce_384(state);
    let key = format!("{}:{}", user_id, nonce);

    write_state(state, application, &key, &state_data).to_one_of_two()?;

    Ok((response, nonce))
}

/// This performs the final login step in the OPAQUE protocol. We retrieve the state using the nonce and provided user_id, making it bound to these and ensuring
/// they are the same values as in the first step. The server generates a secret based on the client request and stored state. If the secret is the same as the
/// client's, we are certain that login succeeded.
fn login_finish(
    state: &mut State,
    application: &str,
    user_id: &str,
    request: &str,
    nonce: &str,
) -> Result<String, OneOf<(Error, OpaqueError)>> {
    // 384 bits nonce, i.e. 48 bytes, 64 base64url characters, which are all 1 byte, so 64 bytes
    assert_eq!(nonce.len(), 64);

    let key = format!("{}:{}", user_id, nonce);

    let state = read_state(state, application, &key).to_one_of_two()?;

    let secret = login_server_finish(request, &state).to_one_of_twond()?;

    Ok(secret)
}

// 1 month
const EXPIRE_TIME: u64 = 30 * 24 * 60 * 60;

fn login_session(
    state: &mut State,
    application: &str,
    user_id: &str,
    request: &str,
    nonce: &str,
    secret: &str,
    requested_claims: Vec<String>,
) -> Result<Vec<u8>, OneOf<(Error, OpaqueError)>> {
    let server_secret = login_finish(state, application, user_id, request, nonce)?;

    if secret != server_secret {
        panic!("Secrets do not match, invalid login!")
    }

    let claims = get_login(state, application, user_id)
        .to_one_of_two()?
        .claims;

    let mut requested_claims: HashSet<String> = HashSet::from_iter(requested_claims);

    let session_claims: Vec<(Value, Value)> = if let Value::Map(entries) = claims {
        entries
            .into_iter()
            .filter(|(key, _value)| {
                if let Value::String(key) = key {
                    if key.is_err() {
                        panic!("Keys must be valid UTF-8!")
                    }

                    let key = key.as_str().unwrap();

                    requested_claims.remove(key)
                } else {
                    panic!("All claims must be string keys!")
                }
            })
            .collect()
    } else {
        panic!("Claims must be a map type!");
    };

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session = Session {
        user_id: user_id.to_owned(),
        expires: time + EXPIRE_TIME,
        session_claims: Value::Map(session_claims),
    };

    let session_encoded = encode::to_vec_named(&session).unwrap();

    Ok(crypto::session(
        &session_encoded,
        &state.private.session,
        state.rng,
    ))
}

#[derive(Debug)]
pub struct InvalidSession {}

fn verify_session_claims(state: &mut State, session: &[u8]) -> Result<Session, InvalidSession> {
    let session =
        crypto::session_decrypt(session, &state.private.session).map_err(|_e| InvalidSession {})?;

    decode::from_read(session.as_slice()).map_err(|_e| InvalidSession {})
}

const LEEWAY: u64 = 10;

fn reset_password(state: &mut State, proof: Proof) -> Result<(), Error> {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if time > proof.expires + LEEWAY {
        panic!("Proof has expired!");
    }

    if let ProofUse::ResetPassword(user_id) = proof.proof_use {
        let state_table_def = state_table(state.tables, &proof.application);
        let signature = b64::URL_SAFE_NO_PAD.decode(&proof.signature).unwrap();

        let write_txn = state.db.begin_write()?;
        {
            let state_table = write_txn.open_table(state_table_def)?;

            // TODO clean up nonces every so often (after expiry)
            let nonce_exists = state_table.get(proof.nonce.as_str())?;

            if nonce_exists.is_some() {
                panic!("Proof has already been used!");
            }

            let key = app_key(state, &proof.application)?;

            let is_verified = verify_signature(
                &proof_data(
                    &proof.application,
                    &proof.nonce,
                    proof.expires,
                    &ProofUse::ResetPassword(user_id.clone()),
                ),
                &signature,
                key,
            );

            if !is_verified {
                panic!("Signature invalid!");
            }

            assert!(set_login_field_write(
                &write_txn,
                state,
                &proof.application,
                &user_id,
                "".to_owned(),
                false
            )?)
        }
        write_txn.commit()?;
    } else {
        // TODO make error
        panic!("Proof for reset password must be reset_password!")
    }

    Ok(())
}

struct PrivateState {
    opaque: String,
    session: SessionKey,
    private: Key,
}

/// It seems like giving them the same lifetime doesn't cause any issues
struct State<'a> {
    tables: &'a mut HashMap<String, String>,
    app_keys: &'a mut HashMap<String, PublicKey>,
    db: &'a Database,
    rng: &'a mut StdRng,
    private: &'a PrivateState,
}

struct StateOwner {
    tables: HashMap<String, String>,
    app_keys: HashMap<String, PublicKey>,
    db: Database,
    rng: StdRng,
    private: PrivateState,
}

impl StateOwner {
    fn setup() -> Result<Self, Error> {
        let db = open_db()?;
        let mut seed = [0u8; 32];
        OsRng.fill(&mut seed);
        let mut rng = StdRng::from_seed(seed);

        let private = init_private_state(&db, &mut rng)?;

        Ok(Self {
            tables: HashMap::new(),
            app_keys: HashMap::new(),
            db,
            rng,
            private,
        })
    }
}

impl<'a> State<'a> {
    fn from_state_owner(state: &'a mut StateOwner) -> Result<Self, Error> {
        Ok(Self {
            tables: &mut state.tables,
            app_keys: &mut state.app_keys,
            db: &state.db,
            rng: &mut state.rng,
            private: &state.private,
        })
    }
}

fn main() {
    let mut state_owner = StateOwner::setup().unwrap();
    let mut state = State::from_state_owner(&mut state_owner).unwrap();

    let value = Login {
        user_id: "hi".to_owned(),
        password_file: "pw".to_owned(),
        claims: Value::Map(Vec::new()),
    };

    let app = "abc".to_owned();

    set_login(&mut state, &value, &app).unwrap();

    let read_login = get_login(&mut state, &app, &value.user_id).unwrap();

    println!("{:?}", read_login)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_borink::client::{
        client_login, client_login_finish, client_register, client_register_finish,
    };

    #[test]
    fn login_set_read() {
        let mut state_owner = StateOwner::setup().unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let value = Login {
            user_id: "hi".to_owned(),
            password_file: "pw".to_owned(),
            claims: Value::Map(Vec::new()),
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
            claims: Value::Map(Vec::new()),
        };

        set_login(state, &value, application).unwrap();

        let (request, client_state) = client_register(password).unwrap();
        let server_response = start_register(state, &request, user_id).unwrap();
        let request = client_register_finish(&client_state, password, &server_response).unwrap();
        register_finish(state, application, &request, user_id, true).unwrap();
    }

    #[test]
    fn register() {
        let mut state_owner = StateOwner::setup().unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

        let user_id = "hi";

        let value = Login {
            user_id: user_id.to_owned(),
            password_file: "".to_owned(),
            claims: Value::Map(Vec::new()),
        };
        let app = "abc";
        let password = "pass";

        create_user(&mut state, user_id, app, password);

        let read_login = get_login(&mut state, app, &value.user_id).unwrap();

        assert_ne!(value.password_file, read_login.password_file)
    }

    #[test]
    fn login() {
        let mut state_owner = StateOwner::setup().unwrap();
        let mut state = State::from_state_owner(&mut state_owner).unwrap();

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
