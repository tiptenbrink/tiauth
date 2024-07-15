use std::collections::VecDeque;
use std::env::current_dir;
use std::{fs, thread};
use tempfile::NamedTempFile;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use redb::{Database, ReadableTableMetadata, TableDefinition};
use std::time::{Duration, Instant};

const ELEMENTS: u64 = 300;
const RNG_SEED: u64 = 3;
const SIZE: u64 = 500;

const TABLE1: TableDefinition<u128, &'static [u8]> = TableDefinition::new("x");
const TABLE2: TableDefinition<u128, &'static [u8]> = TableDefinition::new("y");
const TABLE3: TableDefinition<u128, &'static [u8]> = TableDefinition::new("z1");
const TABLE4: TableDefinition<u128, &'static [u8]> = TableDefinition::new("z2");

#[inline(never)]
fn single_threaded(values: &[(u128, &[u8])]) {
    let tmpfile: NamedTempFile =
        NamedTempFile::new_in(current_dir().unwrap().join(".benchmark")).unwrap();
    let db = Database::builder().create(tmpfile.path()).unwrap();

    let start = Instant::now();
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    for value in values {
        let (key, _) = *value;
        let mut element1 = Vec::new();
        for _ in 0..SIZE {
            let arr: [u8; 32] = rng.gen();
            element1.extend_from_slice(&arr);
        }
        let write_txn = db.begin_write().unwrap();
        {
            let mut table1 = write_txn.open_table(TABLE1).unwrap();
            table1.insert(key, element1.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
        let mut element2 = Vec::new();
        for _ in 0..SIZE {
            let arr: [u8; 32] = rng.gen();
            element2.extend_from_slice(&arr);
        }
        let write_txn = db.begin_write().unwrap();
        {
            let mut table2 = write_txn.open_table(TABLE2).unwrap();
            table2.insert(key, element2.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
        let mut element3 = Vec::new();
        for _ in 0..SIZE {
            let arr: [u8; 32] = rng.gen();
            element3.extend_from_slice(&arr);
        }
        let write_txn = db.begin_write().unwrap();
        {
            let mut table3 = write_txn.open_table(TABLE3).unwrap();
            table3.insert(key, element3.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
        let mut element4 = Vec::new();
        for _ in 0..SIZE {
            let arr: [u8; 32] = rng.gen();
            element4.extend_from_slice(&arr);
        }
        let write_txn = db.begin_write().unwrap();
        {
            let mut table4 = write_txn.open_table(TABLE4).unwrap();
            table4.insert(key, element4.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
    }
    let end = Instant::now();
    let duration = end - start;
    let duration_time = duration.as_secs_f64() * 1000f64;
    println!(
        "single threaded load:  {} inserts in {}ms. {}ms/pair",
        4 * ELEMENTS,
        duration_time,
        duration_time / (4f64 * ELEMENTS as f64)
    );
    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(TABLE1).unwrap();
    assert_eq!(table.len().unwrap(), ELEMENTS);
    let table = read_txn.open_table(TABLE2).unwrap();
    assert_eq!(table.len().unwrap(), ELEMENTS);
    let table = read_txn.open_table(TABLE3).unwrap();
    assert_eq!(table.len().unwrap(), ELEMENTS);
    let table = read_txn.open_table(TABLE4).unwrap();
    assert_eq!(table.len().unwrap(), ELEMENTS);
}

// #[inline(never)]
// fn multi_threaded(values: &[u128]) {
//     let tmpfile: NamedTempFile = NamedTempFile::new_in(current_dir().unwrap().join(".benchmark")).unwrap();
//     let db = Database::builder().create(tmpfile.path()).unwrap();

//     let start = Instant::now();
//     let write_txn = db.begin_write().unwrap();
//     {
//         let mut table1 = write_txn.open_table(TABLE1).unwrap();
//         let mut table2 = write_txn.open_table(TABLE2).unwrap();
//         let mut table3 = write_txn.open_table(TABLE3).unwrap();
//         let mut table4 = write_txn.open_table(TABLE4).unwrap();

//         thread::scope(|s| {
//             s.spawn(|| {
//                 for value in values.iter() {
//                     table1.insert(value, value).unwrap();
//                 }
//             });
//             s.spawn(|| {
//                 for value in values.iter() {
//                     table2.insert(value, value).unwrap();
//                 }
//             });
//             s.spawn(|| {
//                 for value in values.iter() {
//                     table3.insert(value, value).unwrap();
//                 }
//             });
//             s.spawn(|| {
//                 for value in values.iter() {
//                     table4.insert(value, value).unwrap();
//                 }
//             });
//         });
//     }
//     write_txn.commit().unwrap();
//     let end = Instant::now();
//     let duration = end - start;
//     let duration_time = duration.as_secs_f64()*1000f64;
//     println!(
//         "multi threaded load:  {} pairs in {}ms. {}ms/pair",
//         4 * ELEMENTS,
//         duration_time,
//         duration_time/(4f64 * ELEMENTS as f64)
//     );
//     let read_txn = db.begin_read().unwrap();
//     let table = read_txn.open_table(TABLE1).unwrap();
//     assert_eq!(table.len().unwrap(), ELEMENTS);
//     let table = read_txn.open_table(TABLE2).unwrap();
//     assert_eq!(table.len().unwrap(), ELEMENTS);
//     let table = read_txn.open_table(TABLE3).unwrap();
//     assert_eq!(table.len().unwrap(), ELEMENTS);
//     let table = read_txn.open_table(TABLE4).unwrap();
//     assert_eq!(table.len().unwrap(), ELEMENTS);
// }

#[inline(never)]
fn multi_threaded_tx(values: &[(u128, &[u8])]) {
    let tmpfile: NamedTempFile =
        NamedTempFile::new_in(current_dir().unwrap().join(".benchmark")).unwrap();
    let db = Database::builder().create(tmpfile.path()).unwrap();
    let value_keys: Vec<u128> = values.iter().map(|(k, _)| *k).collect();

    let duration_time = thread::scope(|s| {
        s.spawn(|| {
            // Ensure that table 1 has been opened at least
            let mut read_tx = db.begin_read().unwrap();
            //let mut i = 0;
            while read_tx.open_table(TABLE1).is_err() {
                //println!("Doesn't exist! {}", i);
                thread::sleep(Duration::from_millis(10));
                read_tx = db.begin_read().unwrap();
                //i += 1;
            }
            let mut i = 0;
            let start = Instant::now();
            let mut queue = VecDeque::from_iter(value_keys);
            let mut big: Vec<u8> = Vec::with_capacity((SIZE * ELEMENTS) as usize);
            while let Some(key) = queue.pop_front() {
                let read_tx = db.begin_read().unwrap();
                let table = read_tx.open_table(TABLE1).unwrap();
                let val = table.get(key).unwrap();
                let b = if let Some(val) = val {
                    val.value().to_vec()
                } else {
                    queue.push_back(key);
                    Vec::new()
                };
                big.extend(b);
                i += 1;
            }
            let end = Instant::now();
            let duration = end - start;
            let duration_time = duration.as_secs_f64() * 1000f64;
            println!("big size: {}", big.len());
            println!(
                "multi threaded tx read in {}ms with {} reads. {}ms/read",
                duration_time,
                i,
                duration_time / (i as f64)
            );
        });
        let start = Instant::now();
        let j1 = s.spawn(|| {
            let mut rng = StdRng::seed_from_u64(RNG_SEED);
            for (key, _) in values.iter() {
                let mut element = Vec::new();
                for _ in 0..SIZE {
                    let arr: [u8; 32] = rng.gen();
                    element.extend_from_slice(&arr);
                }
                let write_txn = db.begin_write().unwrap();
                {
                    let mut table1 = write_txn.open_table(TABLE1).unwrap();
                    table1.insert(*key, element.as_slice()).unwrap();
                }
                write_txn.commit().unwrap();
            }
        });
        let j2 = s.spawn(|| {
            let mut rng = StdRng::seed_from_u64(RNG_SEED);
            for (key, _) in values.iter() {
                let mut element: Vec<u8> = Vec::new();
                for _ in 0..SIZE {
                    let arr: [u8; 32] = rng.gen();
                    element.extend_from_slice(&arr);
                }
                let write_txn = db.begin_write().unwrap();
                {
                    let mut table2 = write_txn.open_table(TABLE2).unwrap();
                    table2.insert(*key, element.as_slice()).unwrap();
                }
                write_txn.commit().unwrap();
            }
        });
        let j3 = s.spawn(|| {
            let mut rng = StdRng::seed_from_u64(RNG_SEED);
            for (key, _) in values.iter() {
                let mut element = Vec::new();
                for _ in 0..SIZE {
                    let arr: [u8; 32] = rng.gen();
                    element.extend_from_slice(&arr);
                }
                let write_txn = db.begin_write().unwrap();
                {
                    let mut table3 = write_txn.open_table(TABLE3).unwrap();
                    table3.insert(*key, element.as_slice()).unwrap();
                }
                write_txn.commit().unwrap();
            }
        });
        let j4 = s.spawn(|| {
            let mut rng = StdRng::seed_from_u64(RNG_SEED);
            for (key, _) in values.iter() {
                let mut element = Vec::new();
                for _ in 0..SIZE {
                    let arr: [u8; 32] = rng.gen();
                    element.extend_from_slice(&arr);
                }
                let write_txn = db.begin_write().unwrap();
                {
                    let mut table4 = write_txn.open_table(TABLE4).unwrap();
                    table4.insert(*key, element.as_slice()).unwrap();
                }
                write_txn.commit().unwrap();
            }
        });
        j1.join().unwrap();
        j2.join().unwrap();
        j3.join().unwrap();
        j4.join().unwrap();
        let end = Instant::now();
        let duration = end - start;
        duration.as_secs_f64() * 1000f64
    });

    println!(
        "multi threaded tx load:  {} inserts in {}ms. {}ms/pair",
        4 * ELEMENTS,
        duration_time,
        duration_time / (4f64 * ELEMENTS as f64)
    );
    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(TABLE1).unwrap();
    assert_eq!(table.len().unwrap(), ELEMENTS);
    let table = read_txn.open_table(TABLE2).unwrap();
    assert_eq!(table.len().unwrap(), ELEMENTS);
    let table = read_txn.open_table(TABLE3).unwrap();
    assert_eq!(table.len().unwrap(), ELEMENTS);
    let table = read_txn.open_table(TABLE4).unwrap();
    assert_eq!(table.len().unwrap(), ELEMENTS);
}

// TODO: multi-threaded inserts are slower. Probably due to lock contention checking dirty pages

fn main() {
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let mut values_owner: Vec<Vec<u8>> = Vec::new();
    for _ in 0..ELEMENTS {
        let mut element = Vec::new();
        for _ in 0..1 {
            let arr: [u8; 32] = rng.gen();
            element.extend_from_slice(&arr);
        }

        values_owner.push(element)
    }

    let mut values = vec![];
    for i in 0..ELEMENTS {
        values.push((rng.gen(), values_owner[i as usize].as_slice()));
    }

    let tmpdir = current_dir().unwrap().join(".benchmark");
    fs::create_dir(&tmpdir).unwrap();

    //let tmpdir2 = tmpdir.clone();
    // ctrlc::set_handler(move || {
    //     fs::remove_dir_all(&tmpdir2).unwrap();
    //     process::exit(1);
    // })
    // .unwrap();

    single_threaded(&values);

    // multi_threaded(&values);

    multi_threaded_tx(&values);

    fs::remove_dir_all(&tmpdir).unwrap();
}
