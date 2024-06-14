use redb::{Database, Error, ReadableTable, TableDefinition, TypeName, Value};
use opaque_borink::server::register_server;
use std::str;
use std::fmt::Debug;

struct Login<'a> {
    data: &'a [u8],
    user_id_loc: u32,
    user_id_len: u32,
    password_file_loc: u32,
    password_file_len: u32
}

impl<'a> Debug for Login<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Login {{\n\tuser_id: {},\n\tpassword_file: {},\n}}", self.user_id(), self.password_file())
    }
}

struct LoginOwned {
    data: Vec<u8>,
    user_id_loc: u32,
    user_id_len: u32,
    password_file_loc: u32,
    password_file_len: u32
}

impl LoginOwned {
    fn new(user_id: &str, password_file: &str) -> Self {
        // Combined length of user_id and password_file must be < ~4.29 billion bytes (u32::MAX), also leaving space for 8 bytes per field (length and location)
        
        let user_id_len = user_id.len() as u32;
        let password_file_len = password_file.len() as u32;
        let user_id_loc = 16;
        let password_file_loc = user_id_loc + user_id_len;

        let len = (user_id_len + password_file_len) as usize;
        let mut data: Vec<u8> = Vec::with_capacity(len+16);
        data.extend(user_id_loc.to_le_bytes());
        data.extend(user_id_len.to_le_bytes());
        data.extend(password_file_loc.to_le_bytes());
        data.extend(password_file_len.to_le_bytes());
        data.extend_from_slice(user_id.as_bytes());
        data.extend_from_slice(password_file.as_bytes());

        Self {
            data,
            user_id_len,
            user_id_loc,
            password_file_len,
            password_file_loc
        }
    }

    fn login(&self) -> Login {
        Login {
            data: self.data.as_slice(),
            user_id_loc: self.user_id_loc,
            user_id_len: self.user_id_len,
            password_file_len: self.password_file_len,
            password_file_loc: self.password_file_loc
        }
    }
}

fn get_data_u32(data: &[u8], loc: u32, len: u32) -> &[u8] {
    let loc = loc as usize;
    let len = len as usize;

    let range = loc..(loc+len);

    data.get(range).unwrap()
}

impl<'a> Login<'a> {
    fn user_id(&self) -> &'a str {
        let user_id_data = get_data_u32(self.data, self.user_id_loc, self.user_id_len);

        str::from_utf8(user_id_data).unwrap()
    }

    fn password_file(&self) -> &'a str {
        let user_id_data = get_data_u32(self.data, self.password_file_loc, self.password_file_len);

        str::from_utf8(user_id_data).unwrap()
    }
}

impl<'l> Value for Login<'l> {
    type SelfType<'a> = Login<'a>
    where
        Self: 'a;

    type AsBytes<'a> = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a {
        let user_id_loc = u32::from_bytes(data.get(0..4).unwrap());
        let user_id_len = u32::from_bytes(data.get(4..8).unwrap());
        let password_file_loc = u32::from_bytes(data.get(8..12).unwrap());
        let password_file_len = u32::from_bytes(data.get(12..16).unwrap());
        
        Login {
            data,
            user_id_loc,
            user_id_len,
            password_file_loc,
            password_file_len
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b {
        value.data
    }

    fn type_name() -> redb::TypeName {
        TypeName::new("tiauth:login")
    }
}

const TABLE: TableDefinition<&str, Login> = TableDefinition::new("my_data");

fn get() -> Result<(), Error> {
    let db = Database::create("my_db.redb")?;
    let l = LoginOwned::new("user_id1", "pw2");
    let l_db = l.login();
    println!("{:?}", l_db);

    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(TABLE)?;
        table.insert("my_key", l_db)?;
    }
    write_txn.commit()?;

    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(TABLE)?;
    println!("{:?}", table.get("my_key")?.unwrap().value());

    Ok(())
}

fn main() {
    get().unwrap();
}