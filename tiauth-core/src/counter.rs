use std::{
    cmp::Ordering,
    collections::VecDeque,
    io::Cursor,
    mem::MaybeUninit,
    ops::DerefMut,
    sync::{
        atomic::{self, AtomicBool, AtomicU64},
        Arc, Mutex, OnceLock,
    },
    u64,
};

use crate::util::rmp_read_bin;

/// A simple counter with concurrent access.
pub struct Counter {
    counter: AtomicU64,
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

impl Counter {
    // Initialize the counter. No expectation should be set for the initial value. The only guarantee is that the initial value will work with CompactSet.
    pub fn new() -> Self {
        Self {
            // Since we use zero as "empty" in CompactSet, the first value must be 1
            counter: AtomicU64::new(1),
        }
    }

    pub fn increment(&self) -> u64 {
        self.counter.fetch_add(1, atomic::Ordering::Relaxed)
    }

    pub fn to_saved_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let counter_bytes = self.counter.load(atomic::Ordering::Relaxed).to_le_bytes();

        buf.extend_from_slice(&counter_bytes);

        buf
    }

    pub fn from_saved_bytes(bytes: &[u8]) -> Self {
        let bytes: [u8; 8] = bytes.try_into().unwrap();
        let value = u64::from_le_bytes(bytes);

        Self {
            counter: AtomicU64::new(value),
        }
    }
}

/// A data structure that tracks whether it has already seen a u64 value with as little space as possible.
/// Probabilistic data structures (like a Bloom filter) need 10+ bits per element if you want a decent error rate, but
/// our values are in a small(ish) and predictable range. It's designed to use less space than a bit arrray in the case
/// that values are mostly checked in order. If certain values have very large deviations (i.e. they arrive much earlier
/// or later than expected), a bit array might perform better space wise (and it certainly will be better time wise).
/// Until real-world data can be gathered, it will be difficult to evaluate. Currently, the structure is hidden behind
/// a Mutex to allow access from multiple threads.  
pub struct CompactSetRange {
    ranges: Mutex<VecDeque<Range<64>>>,
}

impl Default for CompactSetRange {
    fn default() -> Self {
        Self::new()
    }
}

pub trait CompactSet {
    fn num_exists(&self, num: u64, expires: u64, time: Option<u64>) -> bool;
}

trait CompactSetMeasurable {
    fn current_size(&self) -> usize;
}

impl CompactSet for CompactSetRange {
    fn num_exists(&self, num: u64, expires: u64, time: Option<u64>) -> bool {
        let mut ranges = self.ranges.lock().unwrap();

        let exists = add_num(ranges.deref_mut(), num, expires);

        // Some basic experimentation showed that by doing it every four provides the best space/time tradeoff
        if time.is_some() && num % 4 == 0 {
            check_expired(ranges.deref_mut(), time.unwrap());
        }

        exists
    }
}

impl CompactSetMeasurable for CompactSetRange {
    fn current_size(&self) -> usize {
        self.ranges.lock().unwrap().len() * std::mem::size_of::<Range<64>>()
    }
}

impl CompactSetRange {
    pub fn new() -> Self {
        let mut ranges = VecDeque::new();
        ranges.push_back(Range::new(1));

        Self {
            ranges: Mutex::new(ranges),
        }
    }

    pub fn to_saved_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let ranges = self.ranges.lock().unwrap();

        rmp::encode::write_array_len(&mut buf, ranges.len() as u32).unwrap();
        for r in ranges.iter() {
            rmp::encode::write_bin(&mut buf, &r.serialize()).unwrap();
        }

        buf
    }

    pub fn from_saved_bytes(bytes: &[u8]) -> Self {
        let mut cursor = Cursor::new(bytes);

        let range_len = rmp::decode::read_array_len(&mut cursor).unwrap();
        let mut ranges = VecDeque::with_capacity(range_len as usize);

        for _ in 0..range_len {
            let range_bytes = rmp_read_bin(bytes, &mut cursor).unwrap();
            let range = Range::<64>::deserialize(range_bytes);
            ranges.push_back(range);
        }

        Self {
            ranges: Mutex::new(ranges),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Expiry {
    At(u64),
    Unknown,
}

#[derive(Clone)]
struct Range<const N: usize> {
    members: Option<[u8; N]>,
    min: u64,
    max: u64,
    expires: Expiry,
}

impl<const N: usize> Range<N> {
    fn new(min: u64) -> Self {
        Self {
            members: Some([0u8; N]),
            min,
            max: min + (N as u64) - 1,
            expires: Expiry::Unknown,
        }
    }

    fn full(min: u64, max: u64, expires: Expiry) -> Self {
        assert!(max >= min + (N as u64) - 1);
        Self {
            members: None,
            min,
            max,
            expires,
        }
    }

    fn add_num(&self, num: u64) -> Option<Self> {
        // To conserve space, we represent numbers using the min as offset, because the array won't have a size
        // that can't be represented with a single byte
        // 0 is a special value, it represents the "unfilled" value, therefore 0 can never be used
        let num_small = (num - self.min + 1) as u8;
        self.members.and_then(|mut members| {
            for i in 0..N {
                let val = members[i];
                if val == num_small {
                    return None;
                } else if val == 0 {
                    let members = if i == N - 1 {
                        // In this case we are the last index, so it's full now
                        None
                    } else {
                        members[i] = num_small;
                        Some(members)
                    };

                    return Some(Self {
                        members,
                        min: self.min,
                        max: self.max,
                        expires: self.expires,
                    });
                }
            }

            panic!("Should be space for number!")
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        match self.members {
            Some(members) => {
                rmp::encode::write_bin(&mut buf, &[244]).unwrap();
                rmp::encode::write_bin(&mut buf, &members).unwrap();
            }
            None => {
                rmp::encode::write_bin(&mut buf, &[133]).unwrap();
            }
        }
        rmp::encode::write_u64(&mut buf, self.min).unwrap();
        rmp::encode::write_u64(&mut buf, self.max).unwrap();
        match self.expires {
            Expiry::At(at) => {
                rmp::encode::write_bin(&mut buf, &[66]).unwrap();
                rmp::encode::write_u64(&mut buf, at).unwrap();
            }
            Expiry::Unknown => {
                rmp::encode::write_bin(&mut buf, &[55]).unwrap();
            }
        }

        buf
    }

    fn deserialize(bytes: &[u8]) -> Self {
        let mut cursor = Cursor::new(bytes);

        let members_byte = rmp_read_bin(bytes, &mut cursor).unwrap();
        let members: Option<[u8; N]> = if members_byte == &[244] {
            Some(
                rmp_read_bin(bytes, &mut cursor)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        } else if members_byte == &[133] {
            None
        } else {
            panic!("Expected byte indicating option: 244 or 133!")
        };
        let min = rmp::decode::read_u64(&mut cursor).unwrap();
        let max = rmp::decode::read_u64(&mut cursor).unwrap();
        let expires_byte = rmp_read_bin(bytes, &mut cursor).unwrap();
        let expires: Expiry = if expires_byte == &[66] {
            Expiry::At(rmp::decode::read_u64(&mut cursor).unwrap())
        } else if expires_byte == &[55] {
            Expiry::Unknown
        } else {
            panic!("Expected byte indicating expiry: 366 or 55!");
        };

        Self {
            members,
            min,
            max,
            expires,
        }
    }
}

impl<const N: usize> std::fmt::Debug for Range<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{{}-{};{:?};exp={:?}}}",
            self.min,
            self.max,
            self.members.map(|a| a.map(|v| {
                if v != 0 {
                    (v as u64) + self.min - 1
                } else {
                    0
                }
            })),
            self.expires
        )
    }
}

// impl<const N: usize> PartialOrd for Range<N> {
//     fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
//         match self.expires {
//             Expiry::Unknown => None,
//             Expiry::At(expires) => match other.expires {
//                 Expiry::At(other_expires) => {
//                     Some(expires.cmp(&other_expires))
//                 },
//                 Expiry::Unknown => None,
//             },
//         }
//     }
// }

fn add_num_ranges<const N: usize>(ranges: &mut VecDeque<Range<N>>, num: u64) -> (usize, bool) {
    let n_i = match ranges.binary_search_by(|r| match r.min.cmp(&num) {
        Ordering::Equal => Ordering::Less,
        o => o,
    }) {
        Ok(_) => panic!("Should be no equality!"),
        Err(u) => u,
    };

    let target_i = n_i - 1;

    let initial_max = { ranges[target_i].max };

    if n_i == ranges.len() && num > initial_max {
        let mut max = initial_max;
        while num > max {
            let new_range = Range::<N>::new(max);
            max = new_range.max;
            ranges.push_back(new_range);
        }

        return (ranges.len() - 1, false);
    }

    let target_range = ranges[target_i].add_num(num);

    if target_range.is_none() {
        return (target_i, true);
    }

    let target_range = target_range.unwrap();

    if target_range.members.is_some() {
        ranges[target_i] = target_range;
        return (target_i, false);
    } else {
        ranges[target_i] = target_range.clone();
    }

    let prev_min_exp = (target_i != 0)
        .then(|| {
            let prev = &ranges[target_i - 1];
            if prev.members.is_none() {
                Some((prev.min, prev.expires))
            } else {
                None
            }
        })
        .flatten();

    let next_max = (n_i != ranges.len())
        .then(|| {
            let next = &ranges[n_i];
            if next.members.is_none() {
                Some(next.max)
            } else {
                None
            }
        })
        .flatten();

    let target_i = if prev_min_exp.is_some() && next_max.is_some() {
        let (prev_min, prev_expires) = prev_min_exp.unwrap();
        ranges[target_i - 1] = Range::full(prev_min, next_max.unwrap(), prev_expires);

        if ranges.len() > target_i + 2 {
            for i in target_i..(ranges.len() - 2) {
                ranges[i] = ranges[i + 2].clone()
            }
        }
        ranges.truncate(ranges.len() - 2);
        target_i - 1
    } else if let Some((prev_min, prev_expires)) = prev_min_exp {
        ranges[target_i - 1] = Range::full(prev_min, target_range.max, prev_expires);

        if ranges.len() > target_i {
            for i in target_i..(ranges.len() - 1) {
                ranges[i] = ranges[i + 1].clone()
            }
        }
        ranges.truncate(ranges.len() - 1);
        target_i - 1
    } else if let Some(next_max) = next_max {
        ranges[target_i] = Range::full(target_range.min, next_max, target_range.expires);

        if ranges.len() > target_i + 1 {
            for i in (target_i + 1)..(ranges.len() - 1) {
                ranges[i] = ranges[i + 1].clone()
            }
        }
        ranges.truncate(ranges.len() - 1);
        target_i
    } else {
        target_i
    };

    (target_i, false)
}

// The majority of the time is spent in Range::add_num and binary_search (based on flamegraph)
/// The basic idea is that the data structure consists of a dynamic number of fixed-size ranges. It's inspired
/// by a binary tree map, but is actually stored in a contiguous, sorted vector. When a range is full, it can
/// join adjacent arrays that are also full to reduce the total size. We also track expiry times. When a
/// new value is received in a higher range with an expiry time, we know that all values in earlier ranges
/// must have lesser or equal expiry times. This allows us to mark them as full even if we never receive a
/// value, but they become expired.
fn add_num<const N: usize>(ranges: &mut VecDeque<Range<N>>, num: u64, expires: u64) -> bool {
    let (target_i, contains) = add_num_ranges(ranges, num);

    let exp_i = expired_search(ranges, expires);

    for i in exp_i..target_i {
        ranges[i].expires = Expiry::At(expires)
    }

    contains
}

// fn exp_lin_search<const N: usize>(ranges: &VecDeque<Range<N>>, time: u64) -> usize {
//     for i in 0..ranges.len() {
//         let range = &ranges[i];
//         match range.expires {
//             Expiry::At(at) => {
//                 if at > time {
//                     return i
//                 }
//             },
//             Expiry::Unknown => return i,
//         }
//     }

//     ranges.len()
// }

// Linear search is not faster, but doesn't seem much slower either, but for better worst-case we'll use binary search
fn expired_search<const N: usize>(ranges: &VecDeque<Range<N>>, time: u64) -> usize {
    match ranges.binary_search_by(|r| match r.expires {
        Expiry::At(at) => match at.cmp(&time) {
            Ordering::Equal => Ordering::Less,
            o => o,
        },
        Expiry::Unknown => Ordering::Greater,
    }) {
        Ok(_) => panic!("Should be no equality!"),
        Err(u) => u,
    }
}

// Basically all time is spent in the binary search
fn check_expired<const N: usize>(ranges: &mut VecDeque<Range<N>>, time: u64) {
    //let exp_i = exp_lin_search(ranges, time);
    let exp_i = expired_search(ranges, time);
    let first_min = ranges[0].min;

    if exp_i == 0 {
        return;
    }

    let last_max = ranges[exp_i - 1].max;
    let new_range = Range::full(first_min, last_max, Expiry::At(0));

    ranges.rotate_left(exp_i);
    ranges.truncate(ranges.len() - exp_i);
    ranges.push_front(new_range);
    ranges.shrink_to_fit();
}

// fn check_expired<const N: usize>(ranges: VecDeque<Range<N>>, time: u64) -> VecDeque<Range<N>> {
//     let exp_i = expired_search(&ranges, time);
//     let first_min = ranges[0].min;

//     if exp_i == 0 {
//         return ranges
//     }

//     let last_max = ranges[exp_i-1].max;
//     let new_range = Range::full(first_min, last_max, Expiry::At(0));

//     let mut new_vec = Vec::with_capacity(ranges.len()-exp_i+1);

//     new_vec.push(new_range);
//     new_vec.extend_from_slice(&ranges[exp_i..ranges.len()]);

//     new_vec
// }

// struct BitHole {
//     arr: VecDeque<u8>,
//     offset: usize,
//     first_hole: usize
// }

// const BIT_MASK: [u8; 8] = [128, 64, 32, 16, 8, 4, 2, 1];

// impl BitHole {
//     fn add_num(&mut self, num: usize) -> bool {
//         let b = (num-self.offset)/8;
//         let b_i = num - b*8;
//         while self.arr.len() < b {
//             self.arr.push_back(0);
//         }

//         let exists = self.arr[b] & BIT_MASK[b_i] != 0;
//         if !exists {
//             self.arr[b] += BIT_MASK[b_i];
//         }

//         exists
//     }
// }

#[cfg(test)]
mod test {
    use std::{hint::black_box, time::Instant};

    use rand::{thread_rng, Rng};

    use super::*;
    const RANGE_SIZE: usize = 2;

    #[test]
    fn create() {
        let mut ranges = VecDeque::new();

        for i in 1..10 {
            let mut range = Range::<RANGE_SIZE>::new(i * (RANGE_SIZE as u64));
            if i < 7 {
                range.expires = Expiry::At(i * 100);
            }
            ranges.push_back(range)
        }

        println!("{:?}", ranges);
        let exists = add_num(&mut ranges, 8, 150);
        println!("{:?}", ranges);
        assert!(!exists);
        assert_eq!(ranges[3].members, Some([1, 0]));
        assert_eq!(ranges[2].expires, Expiry::At(150));
        let exists = add_num(&mut ranges, 8, 150);
        assert!(exists);
        assert_eq!(ranges[3].members, Some([1, 0]));

        let exists = add_num(&mut ranges, 9, 125);
        assert!(!exists);
        assert!(ranges[3].members.is_none());
        assert_eq!(ranges[2].expires, Expiry::At(125));

        add_num(&mut ranges, 2, 500);
        add_num(&mut ranges, 3, 500);
        add_num(&mut ranges, 4, 500);
        add_num(&mut ranges, 5, 500);
        assert!(ranges[0].members.is_none());
        assert_eq!(ranges[0].min, 2);
        assert_eq!(ranges[0].max, 5);
        assert!(ranges[1].members.is_some());

        add_num(&mut ranges, 6, 500);
        add_num(&mut ranges, 7, 500);
        assert!(ranges[0].members.is_none());
        assert_eq!(ranges[0].min, 2);
        assert_eq!(ranges[0].max, 9);

        check_expired(&mut ranges, 600);
        assert!(ranges[0].members.is_none());
        assert_eq!(ranges[0].min, 2);
        assert_eq!(ranges[0].max, 13);

        ranges.pop_back();
        ranges.pop_back();
        ranges.pop_back();

        check_expired(&mut ranges, 600);
        assert_eq!(ranges.len(), 1);
        assert!(ranges[0].members.is_none());
        assert_eq!(ranges[0].min, 2);
        assert_eq!(ranges[0].max, 13);

        ranges.push_back(Range::new(14));
        ranges.push_back(Range::new(14 + (RANGE_SIZE as u64)));

        add_num(&mut ranges, 16, 800);

        ranges.pop_back();
        check_expired(&mut ranges, 800);
        assert_eq!(ranges.len(), 1);
        assert!(ranges[0].members.is_none());
        assert_eq!(ranges[0].min, 2);
        assert_eq!(ranges[0].max, 15);

        println!("{:?}", ranges);
    }

    fn lightly_shuffle<T>(vec: &mut [T], max_distance: usize) {
        let mut rng = rand::thread_rng();
        let len = vec.len();

        for i in 0..len {
            let start = if i >= max_distance {
                i - max_distance
            } else {
                0
            };
            let end = if i + max_distance < len {
                i + max_distance
            } else {
                len - 1
            };

            let j = rng.gen_range(start..=end);

            vec.swap(i, j);
        }
    }

    // Experimentation using the below tests shows this is the best option for both space and time
    const ROUTINE_SIZE: usize = 64;

    // When max_distance is 50 (size 50k), it's must more efficient than a bit array
    // When max distance is 2.5k (size 50k), it's less efficient
    // For larger size it's much more efficient except for very significant shuffling
    #[test]
    fn routine() {
        let mut rng = thread_rng();

        // For better benchmark do 500k and 50 amount
        // There it can reach 20M ops/secs
        // `cargo test --package tiauth-core --lib --release --all-features -- counter::test::routine --exact --show-output`
        let size = 5000;
        let amnt = 10;
        let ops = amnt * size;
        let mut add_time = 0f64;
        let mut check_time = 0f64;

        let mut maxes = Vec::new();
        for _ in 0..amnt {
            let mut values = Vec::new();
            let mut expiry: u64 = 0;
            for i in 1..size {
                expiry += rng.gen_range(0..1000);
                values.push((i, expiry));
            }

            lightly_shuffle(&mut values, size / 100);

            let mut ranges: VecDeque<Range<ROUTINE_SIZE>> = VecDeque::new();
            ranges.push_back(Range::new(1));

            let mut max_space = 0;

            let mut time = 0;

            for (i, expires) in values {
                //println!("sp: {}", ranges.len());
                let around: i32 = rng.gen_range(-900..100);
                time = time.max(0.max((expires as i32) + around) as u64);
                let now = Instant::now();
                add_num(&mut ranges, i as u64, expires);
                add_time += now.elapsed().as_secs_f64();
                max_space = max_space.max(ranges.len());
                let now_again = Instant::now();
                if i % 4 == 0 {
                    check_expired(&mut ranges, time);
                }
                check_time += now_again.elapsed().as_secs_f64();
                max_space = max_space.max(ranges.len());
            }

            maxes.push(max_space);
        }

        let max_space: usize = maxes.into_iter().sum::<usize>() / amnt;

        println!(
            "add: {} ops/s.\ncheck: {} ops/s.",
            (ops as f64) / add_time,
            (ops as f64) / check_time
        );
        let mem_size = std::mem::size_of::<Range<ROUTINE_SIZE>>();
        println!(
            "avg max space: {}; mem_size: {}",
            (max_space) * mem_size,
            mem_size
        );
        println!("total {} ops/s.", (ops as f64) / (add_time + check_time));
    }

    #[test]
    fn routine_compactset() {
        let mut rng = thread_rng();

        // For better benchmark do 500k and 50 amount
        // There it can reach 20M ops/secs
        // `cargo test --package tiauth-core --lib --release --all-features -- counter::test::routine --exact --show-output`
        let size = 500000;
        let amnt = 50;
        let ops = amnt * size;
        let mut add_time = 0f64;

        for _ in 0..amnt {
            let mut values = Vec::new();
            let mut expiry: u64 = 0;
            for i in 1..size {
                expiry += rng.gen_range(0..1000);
                values.push((i, expiry));
            }

            lightly_shuffle(&mut values, size / 100);

            let mut ranges: VecDeque<Range<ROUTINE_SIZE>> = VecDeque::new();
            ranges.push_back(Range::new(1));

            let mut compact_set = CompactSetRange::new();

            compact_set.ranges = Mutex::new(ranges);

            let mut time = 0;

            for (i, expires) in values {
                //println!("sp: {}", ranges.len());
                let around: i32 = rng.gen_range(-900..100);
                time = time.max(0.max((expires as i32) + around) as u64);
                let now = Instant::now();
                compact_set.num_exists(i as u64, expires, Some(time));
                add_time += now.elapsed().as_secs_f64();
            }
        }

        println!("total: {} ops/s.", (ops as f64) / add_time);
    }

    #[test]
    fn routine_atomic_bitset() {
        let mut rng = thread_rng();

        // For better benchmark do 500k and 50 amount
        // There it can reach 40M ops/secs
        // `cargo test --package tiauth-core --lib --release --all-features -- counter::test::routine --exact --show-output`
        let size = 500000;
        let amnt = 50;
        let ops = amnt * size;
        let mut add_time = 0f64;

        let mut maxes = Vec::new();
        for _ in 0..amnt {
            let mut values = Vec::new();
            let mut expiry: u64 = 0;
            for i in 1..(size as u64) {
                expiry += rng.gen_range(0..1000);
                values.push((i, expiry));
            }

            lightly_shuffle(&mut values, size / 100);

            let compact_set = AtomicDynamicBitSet::new();

            let mut max_space = 0;

            let mut time = 0;

            let now = Instant::now();
            for (i, expires) in values {
                //println!("sp: {}", ranges.len());
                //let around: i32 = rng.gen_range(-900..100);
                //time = time.max(0.max((expires as i32) + around) as u64);
                
                let result = compact_set.num_exists(i, expires, Some(time));

                if result {
                    black_box(());
                    println!("hu!");
                }
                
                //max_space = 0;
            }
            add_time += now.elapsed().as_secs_f64();

            maxes.push(max_space);
        }

        let max_space: usize = maxes.into_iter().max().unwrap();

        println!(
            "add: {} ops/s. {} us/op.",
            (ops as f64) / add_time,
            (add_time * 1_000_000f64) / (ops as f64)
        );

        println!("avg max space: {}", max_space);
    }
}

struct AtomicU64BitSet(AtomicU64);

impl AtomicU64BitSet {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    fn exists(&self, n: u64) -> bool {
        if n >= 64 {
            panic!("Value must be less than 64!")
        }
        // 0 <= n < 64, so below does not overflow
        let one_at_bit_index = 1u64 << n;
        // shifting a 1 by n means we have a 64 bit number with a 1 at the nth position (0-indexed)
        let old_value = self.0.fetch_or(one_at_bit_index, atomic::Ordering::Relaxed);
        // now we OR with the existing value, which means we have a 1 at the nth position in our atom

        (old_value & one_at_bit_index) > 0
        // one_at_bit_index is 0 except at the nth position (0-indexed) and using AND will only return
        // a non-zero value if the nth position in old_value is 1
    }
}

trait AtomicBitSet {
    fn new() -> Self;

    fn max_n(&self) -> u64;

    fn create_up_to(&self, n: u64);

    fn exists(&self, n: u64) -> bool;
}

const SMALL_SIZE: usize = 32;

/// Occupies roughly 256 bytes for 2048 values
struct AtomicSmallBitSet {
    atoms: [AtomicU64BitSet; SMALL_SIZE],
}

// Initially only 16 bytes, but once the initial 64 values are exhausted the initial allocation take nearly 500 additional bytes
struct AtomicDynamicBitSet {
    initial: AtomicU64BitSet,
    max: u64,
    further: OnceLock<Arc<boxcar::Vec<AtomicU64BitSet>>>,
}

fn further_indexes(n: u64) -> (usize, u64) {
    let n_further = n - 64;
    let atom_index = (n_further as usize) / 64;
    let index_in_bucket = n_further - (atom_index * 64) as u64;

    (atom_index, index_in_bucket)
}

impl AtomicBitSet for AtomicDynamicBitSet {
    fn new() -> Self {
        Self {
            initial: AtomicU64BitSet::new(),
            // We have space  64 * (2^64 - 31 [the max length of the boxcar Vec]) + 64, which is more than u64::MAX
            max: u64::MAX,
            further: OnceLock::new(),
        }
    }

    fn create_up_to(&self, n: u64) {
        if n < 64 {
            return;
        }

        let further = self.further.get_or_init(|| Arc::new(boxcar::Vec::new()));

        let (atom_index, _) = further_indexes(n);

        while further.get(atom_index).is_none() {
            further.push(AtomicU64BitSet::new());
        }
    }

    /// Panics if exists is called for a number for which the bucket does not yet exist. Ensure `create_up_to` has been called for n before.
    fn exists(&self, n: u64) -> bool {
        if n < 64 {
            return self.initial.exists(n);
        }

        let further = self.further.get().unwrap();

        let (atom_index, index_in_bucket) = further_indexes(n);

        let bucket = further.get(atom_index).unwrap();

        bucket.exists(index_in_bucket)
    }

    fn max_n(&self) -> u64 {
        self.max
    }
}

impl AtomicBitSet for AtomicSmallBitSet {
    fn new() -> Self {
        Self {
            atoms: [const { AtomicU64BitSet::new() }; SMALL_SIZE],
        }
    }

    fn max_n(&self) -> u64 {
        ((SMALL_SIZE as u64) * 64) - 1
    }

    fn create_up_to(&self, n: u64) {
        if n > self.max_n() {
            panic!("Cannot create for value greater than max!")
        }
    }

    fn exists(&self, n: u64) -> bool {
        if n > self.max_n() {
            panic!("Cannot check existence for greater than max!")
        }

        let atom_index = n / 64;
        let index_in_atom = n - (atom_index * 64);

        let atom = &self.atoms[index_in_atom as usize];

        atom.exists(index_in_atom)
    }
}

impl AtomicBitSet for AtomicU64BitSet {
    fn new() -> Self {
        Self::new()
    }

    fn max_n(&self) -> u64 {
        63
    }

    fn create_up_to(&self, n: u64) {
        if n > self.max_n() {
            panic!("Cannot create for value greater than max!")
        }
    }

    fn exists(&self, n: u64) -> bool {
        self.exists(n)
    }
}

impl<T: AtomicBitSet> CompactSet for T {
    fn num_exists(&self, num: u64, expires: u64, time: Option<u64>) -> bool {
        self.create_up_to(num);

        self.exists(num)
    }
}
