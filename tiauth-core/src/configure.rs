use redb::Error;
use rmp_serde::encode;

use crate::data::{Application, APPS};
use crate::state::State;

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
