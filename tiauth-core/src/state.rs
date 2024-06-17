#![allow(dead_code)]

use opaque_borink::create_setup;
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, SeedableRng};
use redb::{Database, Error, ReadableTable};
use std::collections::HashMap;

use crate::crypto::{
    create_key, create_session_key, load_key, load_session_key, save_key, save_session_key, Key,
    PublicKey, SessionKey,
};
use crate::data::{open_db, SERVER};

pub struct PrivateState {
    pub opaque: String,
    pub session: SessionKey,
    pub private: Key,
}

/// It seems like giving them the same lifetime doesn't cause any issues
pub struct State<'a> {
    pub tables: &'a mut HashMap<String, String>,
    pub app_keys: &'a mut HashMap<String, PublicKey>,
    pub db: &'a Database,
    pub rng: &'a mut StdRng,
    pub private: &'a PrivateState,
}

pub struct StateOwner {
    tables: HashMap<String, String>,
    app_keys: HashMap<String, PublicKey>,
    db: Database,
    rng: StdRng,
    private: PrivateState,
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

impl StateOwner {
    pub fn setup() -> Result<Self, Error> {
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
    pub fn from_state_owner(state: &'a mut StateOwner) -> Result<Self, Error> {
        Ok(Self {
            tables: &mut state.tables,
            app_keys: &mut state.app_keys,
            db: &state.db,
            rng: &mut state.rng,
            private: &state.private,
        })
    }
}
