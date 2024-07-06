use redb::Error as DbError;

use crate::{Application, State};

fn register_application(state: &mut impl State, application: &Application) -> Result<(), DbError> {
    state.register_application(application, true)
}