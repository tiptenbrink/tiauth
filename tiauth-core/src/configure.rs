use redb::Error;
use rmp_serde::encode;

use crate::data::{Application, APPS};
use crate::state::State;

fn register_application(state: &mut State, application: &Application) -> Result<(), Error> {
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

pub mod test_util {
    use crate::crypto::{create_key, save_key, Key};

    use super::*;

    pub fn create_register_app(state: &mut State, application: &str) -> Key {
        let key = create_key();

        let saved_key = save_key(&key);

        let public_key = saved_key.public;

        let app = Application::new(public_key, application);

        register_application(state, &app).unwrap();

        key
    }
}
