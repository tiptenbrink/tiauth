use std::{cmp::Ordering, collections::VecDeque};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Expiry {
    At(u64),
    Unknown
}

#[derive(Debug, Clone)]
struct Range<const N: usize> {
    members: Option<[u64; N]>,
    min: u64,
    max: u64,
    expires: Expiry
}

impl<const N: usize> Range<N> {
    fn new(min: u64) -> Self {
        Self {
            members: Some([0u64; N]),
            min,
            max: min+(N as u64)-1,
            expires: Expiry::Unknown
        }
    }

    fn full(min: u64, max: u64, expires: Expiry) -> Self {
        assert!(max >= min+(N as u64)-1);
        Self {
            members: None,
            min,
            max,
            expires
        }
    }

    fn add_num(&self, num: u64) -> Option<Self> {
        self.members.and_then(|mut members| {
            for i in 0..N {
                let val = members[i];
                if val == num {
                    return None
                } else if val == 0 {
                    let members = if i == N - 1 {
                        // In this case we are the last index, so it's full now
                        None
                    } else {
                        members[i] = num;
                        Some(members)
                    };
                    
                    return Some(Self {
                        members,
                        min: self.min,
                        max: self.max,
                        expires: self.expires
                    })
                }
            }

            panic!("Should be space for number!")
        })
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
    let n_i = match ranges.binary_search_by(|r| {
        match r.min.cmp(&num) {
            Ordering::Equal => Ordering::Less,
            o => o
        }
    }) {
        Ok(_) => panic!("Should be no equality!"),
        Err(u) => u
    };

    if n_i == 0 {
        println!("{:?}", ranges);
    }

    let target_i = n_i-1;
    let initial_max = {
        ranges[target_i].max
    };

    if n_i == ranges.len() && num > initial_max {
        let mut max = initial_max;
        while num > max {
            let new_range = Range::<N>::new(max);
            max = new_range.max;
            ranges.push_back(new_range);
        }
        
        return (ranges.len()-1, false);
    }
    
    let target_range = (&ranges[target_i]).add_num(num);

    if target_range.is_none() {
        return (target_i, true)
    }

    let target_range = target_range.unwrap();

    if target_range.members.is_some() {
        ranges[target_i] = target_range;
        return (target_i, false)
    } else {
        ranges[target_i] = target_range.clone();
    }
    
    let prev_min_exp= (target_i != 0).then(|| {
        let prev = &ranges[target_i - 1];
        if prev.members.is_none() {
            Some((prev.min, prev.expires))
        } else {
            None
        }
    }).flatten();

    let next_max = (n_i != ranges.len()).then(|| {
        let next = &ranges[n_i];
        if next.members.is_none() {
            Some(next.max)
        } else {
            None
        }
    }).flatten();

    let target_i = if prev_min_exp.is_some() && next_max.is_some() {
        let (prev_min, prev_expires) = prev_min_exp.unwrap();
        ranges[target_i-1] = Range::full(prev_min, next_max.unwrap(), prev_expires);

        if ranges.len() > target_i+2 {
            for i in target_i..(ranges.len()-2) {
                ranges[i] = ranges[i+2].clone()
            }
        }
        ranges.truncate(ranges.len()-2);
        ranges.shrink_to_fit();
        target_i-1
    } else if let Some((prev_min, prev_expires)) = prev_min_exp {
        ranges[target_i-1] = Range::full(prev_min, target_range.max, prev_expires);

        if ranges.len() > target_i {
            for i in target_i..(ranges.len()-1) {
                ranges[i] = ranges[i+1].clone()
            }
        }
        ranges.truncate(ranges.len()-1);
        ranges.shrink_to_fit();
        target_i-1
    } else if let Some(next_max) = next_max {
        ranges[target_i] = Range::full(target_range.min, next_max, target_range.expires);

        if ranges.len() > target_i+1 {
            for i in (target_i+1)..(ranges.len()-1) {
                ranges[i] = ranges[i+1].clone()
            }
        }
        ranges.truncate(ranges.len()-1);
        ranges.shrink_to_fit();
        target_i
    } else {
        target_i
    };
    
    (target_i, false)
} 

fn add_num<const N: usize>(ranges: &mut VecDeque<Range<N>>, num: u64, expires: u64) -> bool {
    let (target_i, contains) = add_num_ranges(ranges, num);

    let exp_i = expired_search(ranges, expires);

    for i in exp_i..target_i {
        ranges[i].expires = Expiry::At(expires)
    }

    contains
}

fn expired_search<const N: usize>(ranges: &VecDeque<Range<N>>, time: u64) -> usize {
    match ranges.binary_search_by(|r| {
        match r.expires {
            Expiry::At(at) => match at.cmp(&time) {
                Ordering::Equal => Ordering::Less,
                o => o
            },
            Expiry::Unknown => Ordering::Greater,
        }
    }) {
        Ok(_) => panic!("Should be no equality!"),
        Err(u) => u
    }
}

fn check_expired<const N: usize>(ranges: &mut VecDeque<Range<N>>, time: u64) {
    let exp_i = expired_search(ranges, time);
    let first_min = ranges[0].min;

    if exp_i == 0 {
        return
    }

    let last_max = ranges[exp_i-1].max;
    let new_range = Range::full(first_min, last_max, Expiry::At(0));

    ranges.rotate_left(exp_i);
    ranges.truncate(ranges.len()-exp_i);
    ranges.push_front(new_range);
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

#[cfg(test)]
mod test {
    use std::{collections::{BTreeMap, BTreeSet, HashMap, HashSet}, time::Instant};

    use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
    use rayon::collections::vec_deque;

    use super::*;
    const RANGE_SIZE: usize = 2;

    #[test]
    fn create() {
        let mut ranges = VecDeque::new();

        for i in 1..10 {
            let mut range = Range::<RANGE_SIZE>::new(i*(RANGE_SIZE as u64));
            if i < 7 {
                range.expires = Expiry::At(i*100);
            }
            ranges.push_back(range)
        }

        let exists = add_num(&mut ranges, 8, 150);
        assert!(!exists);
        assert_eq!(ranges[3].members, Some([8, 0]));
        assert_eq!(ranges[2].expires, Expiry::At(150));
        let exists = add_num(&mut ranges, 8, 150);
        assert!(exists);
        assert_eq!(ranges[3].members, Some([8, 0]));

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
        ranges.push_back(Range::new(14+(RANGE_SIZE as u64)));

        add_num(&mut ranges, 16, 800);

        ranges.pop_back();
        check_expired(&mut ranges, 800);
        assert_eq!(ranges.len(), 1);
        assert!(ranges[0].members.is_none());
        assert_eq!(ranges[0].min, 2);
        assert_eq!(ranges[0].max, 15);
        
        println!("{:?}", ranges);
    }

    fn lightly_shuffle<T>(vec: &mut Vec<T>, max_distance: usize) {
        let mut rng = rand::thread_rng();
        let len = vec.len();
    
        for i in 0..len {
            let start = if i >= max_distance { i - max_distance } else { 0 };
            let end = if i + max_distance < len { i + max_distance } else { len - 1 };
    
            let j = rng.gen_range(start..=end);
    
            vec.swap(i, j);
        }
    }

    // Experimentation using the below tests shows this is the best option for both space and time
    const ROUTINE_SIZE: usize = 64;

    // When max_distance is 50 (size 50k), it's must more efficient than a bit array
    // When max distance is 2.5k (size 50k), it's less efficient
    // Same holds for much larger size
    #[test]
    fn routine() {
        let mut rng = thread_rng();

        let size = 500000;
        let amnt = 10;
        let ops = amnt*size;
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
            
            lightly_shuffle(&mut values, size/1000);

            let mut ranges: VecDeque<Range<ROUTINE_SIZE>> = VecDeque::new();
            ranges.push_back(Range::new(1));

            let mut max_space = 0;

            let mut time = 0;
            
            for (i, expires) in values {
                let around: i32 = rng.gen_range(-900..900);
                time = time.max(0.max((expires as i32)+around) as u64);
                let now = Instant::now();
                add_num(&mut ranges, i as u64, expires);
                add_time += now.elapsed().as_secs_f64();
                max_space = max_space.max(ranges.len());
                let now_again = Instant::now();
                if i % 5 == 0 {
                    check_expired(&mut ranges, time);
                }
                check_time += now_again.elapsed().as_secs_f64();
                max_space = max_space.max(ranges.len());
            }

            maxes.push(max_space);
        }

        let max_space: usize = maxes.into_iter().sum::<usize>()/amnt;

        println!("add: {} ops/s.\ncheck: {} ops/s.", (ops as f64)/add_time, (ops as f64)/check_time);
        println!("avg max space: {}", (max_space)*(std::mem::size_of::<Range<ROUTINE_SIZE>>()));
    }
}