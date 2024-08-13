use std::{array, borrow::Borrow, cell::UnsafeCell, collections::HashMap, fmt::Debug, hash::Hash, mem::MaybeUninit, sync::{atomic::{self, AtomicBool, AtomicU64, AtomicUsize}, Arc, OnceLock}, time::Instant};

use thiserror::Error;

/// An append-only vector stored on the heap, with fixed capacity and with a cheaply-clonable view into its contents. 
/// It is initialized on the heap, so it will not overflow the stack even during initialization. The cheap view comes
/// from its elements being stored behind an Arc. Only mutable references to the original AppendOnlyArcVec are able
/// to insert additional entries. Its memory will be reclaimed when both the AppendOnlyArcVec has been dropped and
/// when there are no more views.
struct AppendOnlyArcVec<T> {
    index: usize,
    capacity: usize,
    elements: Arc<[OnceLock<T>]>
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

fn get_from_elements<T>(elements: &Arc<[OnceLock<T>]>, i: usize) -> Option<&T> {
    elements.get(i).and_then(|e| {
        e.get()
    })
}

impl<T> AppendOnlyArcVec<T> {
    fn new(capacity: usize) -> Self {
        // We do the below to ensure we do not overflow the stack while creating the Vector, because otherwise we would have to first create an array on the stack
        let mut vec: Vec<OnceLock<T>> = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            vec.push(OnceLock::new())
        }
        
        Self {
            index: 0,
            capacity,
            elements: Arc::from(vec)
        }
    }

    fn view(&self) -> VectorView<T> {
        VectorView {
            elements: self.elements.clone()
        }
    }

    fn push(&mut self, value: T) -> Result<usize, CapacityError> {
        let i = self.index;
        if i >= self.capacity {
            return Err(CapacityError)
        }
        self.index += 1;
        // We do ok() here so we don't have to implement Debug
        // We can unwrap because this method requires a mutable reference meaning there can only exist one, so no other threads can concurrently push
        self.elements[i].set(value).ok().unwrap();
        Ok(i)
    }

    fn get(&self, i: usize) -> Option<&T> {
        get_from_elements(&self.elements, i)
    }
}

impl<T> VectorView<T> {
    fn get(&self, i: usize) -> Option<&T> {
        get_from_elements(&self.elements, i)
    }
}

/// The VersionMap is a map that provides a cheap view into its contents that is concurrently accessible. To allow this, it uses an append-only backing store with a fixed capacity.
/// This means that once inserted, an element's memory will not be reclaimed until the entire VersionMap is dropped.
pub struct VersionMap<K, V> {
    map: HashMap<K, usize>,
    version: Arc<AtomicU64>,
    vec: AppendOnlyArcVec<V>
}


pub struct VersionMapView<K: Clone, V> {
    map: HashMap<K, usize>,
    current: u64,
    version: Arc<AtomicU64>,
    vec: VectorView<V>
}

impl<K: Clone, V> Clone for VersionMapView<K, V> {
    fn clone(&self) -> Self {
        Self { map: self.map.clone(), current: self.current.clone(), version: self.version.clone(), vec: self.vec.clone() }
    }
}

impl<K, V> VersionMap<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            version: Arc::new(AtomicU64::new(0)),
            vec: AppendOnlyArcVec::new(capacity)
        }
    }

    pub fn view(&self) -> VersionMapView<K, V> 
        where K: Clone
    {
        VersionMapView {
            map: self.map.clone(),
            current: self.version.load(atomic::Ordering::Acquire),
            version: self.version.clone(),
            vec: self.vec.view()
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Result<Option<&V>, CapacityError>
    where
        K: Eq + Hash
    {
        self.version.fetch_add(1, atomic::Ordering::AcqRel);
        let index = self.vec.push(value)?;
        let previous = self.map.insert(key, index);
        Ok(previous.and_then(|i| self.vec.get(i)))
    }
}

#[derive(Debug)]
pub struct OutdatedError;

impl<K: Clone, V> VersionMapView<K, V> {
    pub fn get<Q>(&self, key: &Q) -> Result<Option<&V>, OutdatedError>
    where
        K: Borrow<Q> + Eq + Hash,
        Q: Eq + Hash + ?Sized
    {
        if self.version.load(atomic::Ordering::Acquire) > self.current {
            return Err(OutdatedError)
        }

        Ok(self.map.get(key).and_then(|i| {
            self.vec.get(*i)
        }))
    }
}

const SIZE: usize = 5000;

mod test {
    use super::*;

    #[test]
    fn test_versionmap() {
        println!("{}", "hi");
        let mut lmap: HashMap<String, usize> = HashMap::new();
        let mut vmap = VersionMap::<_, _>::new(SIZE);
        let size = SIZE;
        let mut o_loc = 0;
        for i in 0..size {
            
            if i == size-2 {
                lmap.insert("basbas".to_owned(), i);
                vmap.insert("basbas".to_owned(), i);
            } else {
                lmap.insert(format!("abcasdfasdfaeawyawanawrawrh{}", i), i);
                vmap.insert(format!("abcasdfasdfaeawyawanawrawrh{}", i), i);
            }   
        }
        
        let times = 10000;

        let mut b = 0;
        let o_view = vmap.view();
        let now = Instant::now();
        for i in 0..times {
            b = *o_view.get("basbas").unwrap().unwrap();
        }
        let end = now.elapsed().as_secs_f64()*1000000f64/(times as f64);

        println!("{}: {} us.", b, end);
    }

}