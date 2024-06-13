use redb::{Database, Error, ReadableTable, TableDefinition};
use opaque_borink::server::register_server;

struct Login {

}

const TABLE: TableDefinition<&str, u64> = TableDefinition::new("my_data");

fn get() -> Result<(), Error> {
    let db = Database::create("my_db.redb")?;
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(TABLE)?;
        table.insert("my_key", &123)?;
    }
    write_txn.commit()?;

    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(TABLE)?;
    println!("{}", table.get("my_key")?.unwrap().value());

    Ok(())
}

fn main() {
    println!("hello");

    get().unwrap();
}