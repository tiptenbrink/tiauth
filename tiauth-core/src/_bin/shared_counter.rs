use crossbeam::channel::bounded;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, sleep};
use std::time::Duration;

fn main() {
    let counter = Arc::new(AtomicU64::new(0));
    let mut handles = vec![];

    use std::time::Instant;

    let (s, r) = bounded(1);

    let tot = 1000000;
    let nr = 100;
    let inr = tot / nr;
    let tot = inr * nr;
    for _ in 0..nr {
        let counter = Arc::clone(&counter);
        let t_r = r.clone();
        let handle = thread::spawn(move || {
            loop {
                sleep(Duration::from_micros(1));
                if !t_r.is_empty() {
                    break;
                }
            }

            //let mut seen = Vec::new();

            for _ in 0..inr {
                let prev_num = counter.fetch_add(1, Ordering::Relaxed);
                let num = prev_num + 1;
                //seen.push(num);
            }

            //seen
        });
        handles.push(handle);
    }

    let now = Instant::now();
    s.send(0).unwrap();
    let elapsed = loop {
        sleep(Duration::from_millis(1));
        let num = counter.load(Ordering::Relaxed);
        if num == tot {
            break now.elapsed();
        }
    };
    //let mut all_seen = HashSet::new();
    for handle in handles {
        handle.join().unwrap();
        //all_seen.extend(seen);
    }
    //assert_eq!((all_seen.len() as u64), tot);
    //let elapsed = now.elapsed();
    let result = counter.load(Ordering::Relaxed);
    assert_eq!(result, tot);

    println!("Result: {}", result);

    println!("{} ops/sec", (tot as f64) / elapsed.as_secs_f64());
}

// fn main() {
//     let counter = Arc::new(Mutex::new(0u32));
//     let mut handles = vec![];

//     use std::time::Instant;

//     let (s, r) = bounded(1);

//     let tot = 10000;
//     let nr = 20;
//     let inr = tot/nr;
//     let tot = inr*nr;
//     for _ in 0..nr {
//         let counter = Arc::clone(&counter);
//         let t_r = r.clone();
//         let handle = thread::spawn(move || {

//             loop {
//                 sleep(Duration::from_micros(1));
//                 if !t_r.is_empty() {
//                     break;
//                 }
//             }

//             for _ in 0..inr {
//                 let num = {
//                     let mut num = counter.lock().unwrap();

//                     *num += 1;

//                     *num
//                 };
//             }

//         });
//         handles.push(handle);
//     }

//     let now = Instant::now();
//     s.send(0).unwrap();
//     let elapsed = loop {
//         sleep(Duration::from_millis(1));
//         let num = counter.lock().unwrap();
//         if *num == tot {
//             break now.elapsed()
//         }
//     };
//     for handle in handles {
//         handle.join().unwrap();
//     }
//     //let elapsed = now.elapsed();
//     assert_eq!(*counter.lock().unwrap(), tot);

//     println!("Result: {}", *counter.lock().unwrap());

//     println!("{} ops/sec", (tot as f64)/elapsed.as_secs_f64());
// }
