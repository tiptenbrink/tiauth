use std::{array, borrow::Borrow, cell::UnsafeCell, collections::HashMap, fmt::Debug, hash::{Hash, RandomState}, marker::PhantomData, mem::MaybeUninit, sync::{atomic::{self, AtomicBool, AtomicU64, AtomicUsize}, Arc, OnceLock}, time::Instant};
use std::hash::BuildHasher;
use thiserror::Error;

pub struct PushMode;

pub struct SetMode;

trait VecMode {

}

impl VecMode for PushMode {}
impl VecMode for SetMode {}

/// An append-only vector stored on the heap, with fixed capacity and with a cheaply-clonable view into its contents. 
/// It is initialized on the heap, so it will not overflow the stack even during initialization. The cheap view comes
/// from its elements being stored behind an Arc. Only mutable references to the original AppendOnlyArcVec are able
/// to insert additional entries. Its memory will be reclaimed when both the AppendOnlyArcVec has been dropped and
/// when there are no more views.
/// 
/// Depending on its mode, it is either pushed to, where it returns the index, or it is set to, which means its
/// indexes must be managed elsewhere. Regardless of the mode, it will return an Error when its capacity is reached.
struct AppendOnlyArcVec<T, M: VecMode> {
    capacity: usize,
    used: usize,
    elements: Arc<[OnceLock<T>]>,
    phantom: PhantomData<M>
}

/// A view into a group of elements stored on the heap. The view is cheaply clonable, as the elements are stored
/// behind an Arc.
struct VectorView<T> {
    elements: Arc<[OnceLock<T>]>
}

impl<T> Clone for VectorView<T> {
    fn clone(&self) -> Self {
        Self { elements: self.elements.clone() }
    }
}

#[derive(Debug, Error)]
#[error("Vector has reached maximum capacity!")]
pub struct CapacityError;

/// Once is designed to be really cheap to read. As such, getting is a very fast operation if we know the index.
fn get_from_elements<T>(elements: &Arc<[OnceLock<T>]>, i: usize) -> Option<&T> {
    elements.get(i).and_then(|e| {
        e.get()
    })
}

pub trait ReadableVector<T> {
    fn get(&self, i: usize) -> Option<&T>;
}

impl<T, M: VecMode> AppendOnlyArcVec<T, M> {
    fn new(capacity: usize) -> Self {
        // We do the below to ensure we do not overflow the stack while creating the Vector, because otherwise we would have to first create an array on the stack
        let mut vec: Vec<OnceLock<T>> = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            vec.push(OnceLock::new())
        }
        
        Self {
            used: 0,
            capacity,
            elements: Arc::from(vec),
            phantom: PhantomData
        }
    }

    fn view(&self) -> VectorView<T> {
        VectorView {
            elements: self.elements.clone()
        }
    }

    // Since [T] is unsized, we can't do into_inner on the Arc to recover what's inside
}

impl<T> AppendOnlyArcVec<T, PushMode> {
    fn push(&mut self, value: T) -> Result<usize, CapacityError> {
        let i = self.used;
        if i >= self.capacity {
            return Err(CapacityError)
        }
        self.used += 1;
        // We do ok() here so we don't have to implement Debug
        // We can unwrap because this method requires a mutable reference meaning there can only exist one, so no other threads can concurrently push
        self.elements[i].set(value).ok().unwrap();
        Ok(i)
    }
}

impl<T> AppendOnlyArcVec<T, SetMode> {
    fn set(&mut self, value: T, i: usize) -> Result<(), CapacityError> {
        if self.used >= self.capacity {
            return Err(CapacityError)
        }
        // We do ok() here so we don't have to implement Debug
        // Setting a previously set value panics
        self.elements[i].set(value).ok().unwrap();
        Ok(())
    }
}

impl<T, M: VecMode> ReadableVector<T> for AppendOnlyArcVec<T, M> {
    fn get(&self, i: usize) -> Option<&T> {
        get_from_elements(&self.elements, i)
    }
}

impl<T> ReadableVector<T> for VectorView<T> {
    fn get(&self, i: usize) -> Option<&T> {
        get_from_elements(&self.elements, i)
    }
}

/// AppendOnlyArcMap is a map that provides a cheap view into its contents that is concurrently accessible. To allow 
/// this, it uses an append-only backing store with a fixed capacity. This means that once inserted, an element's 
/// memory will not be reclaimed until the entire VersionMap is dropped. Furthermore, a certain key can be inserted
/// only once. Subsequent insertions of the same key will simply return the first value set. 
/// 
/// The map and view is designed for single writer, multiple reader usecases. Reads are very fast, as fast as reading
/// a `std` [`OnceLock`] is on the same platform (which despite the name ). The map is implemented as a simplified 
/// hash map, using `std`'s [`RandomState`], open addressing and quadratic probing. It's not designed to be very 
/// space-efficient (it can use up to twice the requested capacity) and will definitely not be extremely competitive, 
/// but it should not be too far off and works well for its intended use case.
pub struct AppendOnlyArcMap<K, V> {
    state: RandomState,
    map: AppendOnlyArcVec<(K, V), SetMode>
}

/// MapView provides a read-only view into a AppendOnlyArcMap that is fully synchronized with the backing map.
pub struct MapView<K, V> {
    state: RandomState,
    capacity: usize,
    map: VectorView<(K, V)>
}

impl<K, V> Clone for MapView<K, V> {
    /// This will cheaply clone the view, as it only involves cloning Arc's and a small amount of other data.
    fn clone(&self) -> Self {
        Self { state: self.state.clone(), capacity: self.capacity, map: self.map.clone() }
    }
}

impl<K, V> AppendOnlyArcMap<K, V> {
    /// Initialize a AppendOnlyArcMap with the given capacity. Note that the capacity is how many different keys
    /// can be inserted, as deletions are not possible. Also note that the entire capacity is allocated, so don't 
    /// give it a capacity much higher than you expect to need.
    /// 
    /// The envisioned use case involves occasionally recycling the entire map when more capacity is required, but
    /// this is left to the application.
    pub fn new(capacity: usize) -> Self 
        where K: Clone
    {
        // We always want a power of two capacity, so we pick the next power of two such that the requested capacity is
        // less than 75% of the real capacity. This ensures a good load factor.
        let next_power = capacity.next_power_of_two();
        let capacity = if next_power as f64 >= (capacity as f64) / 0.75 {
            next_power
        } else {
            next_power.next_power_of_two()
        };
        Self {
            state: RandomState::new(),
            map: AppendOnlyArcVec::new(capacity)
        }
    }

    /// Returns a clone of the AppendOnlyArcMap, referring to the same backing store. It also includes the RandomState
    /// and capacity to allow computing indexes.
    pub fn view(&self) -> MapView<K, V>
    {
        MapView {
            map: self.map.view(),
            state: self.state.clone(),
            capacity: self.map.capacity.clone()
        }
    }

    /// Inserts a value. If a previous value exists, a reference to it will be returned and nothing will be inserted, 
    /// otherwise this function returns None. If the backing store has run out of capacity, a CapacityError is raised.
    /// This should only happen if there are more keys inserted than the capacity requested at initialization.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<&V>, CapacityError>
    where
        K: Eq + Hash + Clone
    {
        match search(&self.state, &self.map, self.map.capacity, key.borrow()) {
            Ok(target) => {
                return Ok(Some(&self.map.get(target).unwrap().1))
            },
            Err(index) => {
                self.map.set((key, value), index)?;
                Ok(None)
            }
        }
    }

    // pub fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iterator: I) -> Result<(), CapacityError>
    // where
    //     K: Eq + Hash + Clone
    // {
    //     let mut new_map = HashMap::new();
    //     new_map.clone_from(&self.map);
    //     for (key, value) in iterator.into_iter() {
    //         self.version.fetch_add(1, atomic::Ordering::AcqRel);
    //         let index = self.vec.push(value)?;
    //         new_map.insert(key, index);
    //     }
    //     self.map = Arc::new(new_map);
    //     Ok(())
    // }

    // fn search<Q>(&self, key: &Q) -> Result<usize, usize>
    // where
    //     K: Borrow<Q>,
    //     Q: Eq + Hash + ?Sized {
    //     let key_hash = self.state.hash_one(key);
    //     let mut i = 0;
    //     let mut index_incr = 0;
    //     let mut index = (key_hash % (self.map.capacity as u64)) as usize;
    //     loop {
    //         if i == self.map.capacity {
    //             panic!("Should have found key or null key after full iteration!")
    //         }
    //         match self.map.get(index) {
    //             Some((k, _)) => {
    //                 if k.borrow() == key {
    //                     // We would like to immediately return v, but that's no use because of borrow checker limitations
    //                     // See https://blog.rust-lang.org/2022/08/05/nll-by-default.html and the RFC for NLL, we need Polonius
    //                     return Ok(index)
    //                 }
    //             },
    //             None => return Err(index),
    //         }

    //         i += 1;
    //         // Quadratic probing using triangular numbers
    //         index_incr += 1;
    //         index = (index + index_incr) % self.map.capacity;
    //     };
    // }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q> + Eq + Hash,
        Q: Eq + Hash + ?Sized {
        search(&self.state, &self.map, self.map.capacity, key).ok().map(|index| {
            &self.map.get(index).unwrap().1
        })
    }
}

fn search<K, Q, V, M: ReadableVector<(K, V)>>(state: &RandomState, map: &M, capacity: usize, key: &Q) -> Result<usize, usize>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized {
        let key_hash = state.hash_one(key);
        let mut i = 0;
        let mut index_incr = 0;
        let mut index = (key_hash % (capacity as u64)) as usize;
        loop {
            if i == capacity {
                panic!("Should have found key or null key after full iteration!")
            }
            match map.get(index) {
                Some((k, _)) => {
                    if k.borrow() == key {
                        // We would like to immediately return v, but that's no use because of borrow checker limitations
                        // See https://blog.rust-lang.org/2022/08/05/nll-by-default.html and the RFC for NLL, we need Polonius
                        return Ok(index)
                    }
                },
                None => return Err(index),
            }

            i += 1;
            // Quadratic probing using triangular numbers
            index_incr += 1;
            index = (index + index_incr) % capacity;
        };
    }

impl<K, V> MapView<K, V> {
    /// Gets the value for the given key at the correct index. The backing store can be updated concurrently, but
    /// will not change, so if a value is returned, that same value is guaranteed to be returned for the same key for
    /// future calls.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q> + Eq + Hash,
        Q: Eq + Hash + ?Sized {
        search(&self.state, &self.map, self.capacity, key).ok().map(|index| {
            &self.map.get(index).unwrap().1
        })
    }
}

const SIZE: usize = 100000;

mod test {
    use super::*;

    #[test]
    fn test_appendonlymap() {
        let mut vmap = AppendOnlyArcMap::<_, _>::new(SIZE+20);
        let size = SIZE;
        println!("huh");
        for i in 0..10 {
            //let inst = Instant::now();
            vmap.insert(format!("asasfdjl;askdf{}", i), i).unwrap();
            //let end = inst.elapsed().as_secs_f64()*1000000f64;
            //println!("i: {}. {} us.", i, end);
        }
        vmap.insert("basbas".to_owned(), SIZE).unwrap();

        let times = 10000;

        let mut b = 0;
        let o_view = vmap.view();
        let now = Instant::now();
        for _ in 0..times {
            b = *o_view.get("basbas").unwrap();
        }
        let end = now.elapsed().as_secs_f64()*1000000f64/(times as f64);

        println!("{}: {} us.", b, end);
    }

}