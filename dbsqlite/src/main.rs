use std::error::Error;

fn main() {
    match dbsqlite::run() {
        Ok(()) => (),
        Err(e) => {
            println!("{:?}", e);
        }
    };
}