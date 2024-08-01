use crossbeam::channel::{self, Receiver, RecvTimeoutError, Sender};
use rand::{rngs::StdRng, Rng, SeedableRng};
use redb::{Database, ReadableTable, TableDefinition};
use std::{
    env::current_dir,
    fs,
    path::{Path, PathBuf},
    process,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;

#[derive(Clone, Debug)]
struct SessionInfo {
    session_id: u128,
    family: [u8; 64],
}

struct CreateSession {
    session: SessionInfo,
    result: Sender<CreateSessionResult>,
}

impl CreateSession {
    fn new(session: SessionInfo) -> (Self, Receiver<CreateSessionResult>) {
        let (s, r) = channel::bounded(1);
        (Self { session, result: s }, r)
    }
}

#[derive(Debug, PartialEq)]
enum CreateSessionResult {
    AlreadyExists,
    Success,
}

impl SessionInfo {
    fn serialize(self) -> Vec<u8> {
        let mut buf = self.family.to_vec();
        let id_bytes = self.session_id.to_le_bytes();
        buf.extend_from_slice(&id_bytes);

        buf
    }

    fn deserialize(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 80);

        let (family, id_bytes) = bytes.split_at(64);
        let session_id_arr: [u8; 16] = id_bytes.try_into().unwrap();

        let session_id = u128::from_le_bytes(session_id_arr);

        Self {
            family: family.try_into().unwrap(),
            session_id,
        }
    }
}

fn session_id() -> SessionInfo {
    let mut rng = StdRng::from_entropy();
    let mut family = [0u8; 64];

    rng.fill(family.as_mut_slice());
    let session_id: u128 = rng.gen();

    SessionInfo { family, session_id }
}

// the u32 is a bit flag.
// 0 default state
// 1 = revoked
const SESSIONS: TableDefinition<&'static [u8], u32> = TableDefinition::new("sessions");
const SESSION_SYNC: TableDefinition<&'static [u8], u32> = TableDefinition::new("sessions_sync");

///
/// Suppose an attacker received an Ephemeral from login_start and wishes to create two valid Sessions.
/// They make two concurrent requests. While the "state" value is used to decide which thread to call (hash),
/// we still want to be resilient against the case where both requests are made to different threads.
/// Since no Session was yet created, both threads will accept it and write to their databases.
/// Now the threads synchronize. Since normal operation would never lead to two requests for the same login_start,
/// we simply revoke the Session. A revokation on a thread always trumps any active status.

fn write_session(session: SessionInfo, sender: Sender<CreateSession>) -> CreateSessionResult {
    let (sess, r) = CreateSession::new(session);
    sender.send(sess).unwrap();
    let result = r.recv().unwrap();
    //println!("result: {:?}", result);
    result
}

fn synchronize(
    db: &Database,
    sync_s: Sender<(SessionInfo, u32)>,
    sync_r: Receiver<(SessionInfo, u32)>,
) {
    thread::scope(|s| {
        s.spawn(|| while let Ok(session) = sync_r.recv() {});
    });
}

fn open_db_thread(path: PathBuf, rcv: Receiver<CreateSession>) -> JoinHandle<()> {
    thread::spawn(move || {
        let db = Database::create(path).unwrap();

        loop {
            let CreateSession { session, result } =
                match rcv.recv_timeout(Duration::from_millis(10)) {
                    Ok(create_session) => create_session,
                    Err(RecvTimeoutError::Disconnected) => panic!("Disconnected!"),
                    Err(RecvTimeoutError::Timeout) => {
                        //synchronize(&db);
                        continue;
                    }
                };

            let write_txn = db.begin_write().unwrap();

            let session_bytes = session.serialize();
            let session_bytes = session_bytes.as_slice();

            let exists = {
                let table = write_txn.open_table(SESSIONS).unwrap();

                let value = table.get(session_bytes).unwrap();

                value.is_some()
            };

            if exists {
                result.send(CreateSessionResult::AlreadyExists).unwrap();
                continue;
            }

            {
                let mut table = write_txn.open_table(SESSIONS).unwrap();

                table.insert(session_bytes, 0).unwrap();

                let mut table = write_txn.open_table(SESSION_SYNC).unwrap();

                table.insert(session_bytes, 0).unwrap();
            }

            write_txn.commit().unwrap();

            result.send(CreateSessionResult::Success).unwrap();
        }
    })
}

fn main() {
    let tmpdir = current_dir().unwrap().join(".benchmark");
    fs::create_dir(&tmpdir).unwrap();

    let tmpdir_handler = tmpdir.clone();
    ctrlc::set_handler(move || {
        fs::remove_dir_all(&tmpdir_handler).unwrap();
        process::exit(1);
    })
    .unwrap();

    let (snd, rcv) = channel::bounded(20);

    let join = thread::spawn(move || {
        let mut joins: Vec<JoinHandle<_>> = Vec::new();
        for _ in 0..4 {
            let tmpfile: NamedTempFile =
                NamedTempFile::new_in(current_dir().unwrap().join(".benchmark")).unwrap();
            let ijoin = open_db_thread(tmpfile.path().to_owned(), rcv.clone());
            joins.push(ijoin);
        }

        for j in joins {
            j.join().unwrap();
        }
    });

    let start = Instant::now();
    thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                for _ in 0..300 {
                    let sess = session_id();
                    let result = write_session(sess.clone(), snd.clone());
                    assert_eq!(result, CreateSessionResult::Success)
                }
            });
        }
    });

    let end = Instant::now();
    let duration = end - start;
    let duration_time = duration.as_secs_f64() * 1000f64;
    println!(
        "single threaded load:  {} inserts in {}ms. {}ms/pair",
        300 * 4,
        duration_time,
        duration_time / (4f64 * 300 as f64)
    );

    join.join().unwrap();

    fs::remove_dir_all(&tmpdir).unwrap();
}
