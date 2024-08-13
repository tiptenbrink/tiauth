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

/// Once is designed to be really cheap to read. As such, getting is a very fast operation if we know the index.
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

/// VersionMap is a map that provides a cheap view into its contents that is concurrently accessible. To allow 
/// this, it uses an append-only backing store with a fixed capacity. This means that once inserted, an element's 
/// memory will not be reclaimed until the entire VersionMap is dropped.
/// 
/// It contains a "version" that is incremented whenever a new element is inserted. This allows views to know they are 
/// outdated.
pub struct VersionMap<K, V> {
    map: Arc<HashMap<K, usize>>,
    version: Arc<AtomicU64>,
    vec: AppendOnlyArcVec<V>
}

/// VersionMapView provides a view into a VersionMap. While its backing store will allways be up to date, the indexes
/// in the backing store are only known from an internal map, which might become outdated as the original VersionMap is 
/// updated concurrently. 
pub struct VersionMapView<K, V> {
    map: Arc<HashMap<K, usize>>,
    current: u64,
    version: Arc<AtomicU64>,
    vec: VectorView<V>
}

impl<K, V> Clone for VersionMapView<K, V> {
    /// This will cheaply clone the view, as it only involves cloning Arc's and the current version.
    fn clone(&self) -> Self {
        Self { map: self.map.clone(), current: self.current.clone(), version: self.version.clone(), vec: self.vec.clone() }
    }
}

impl<K, V> VersionMap<K, V> {
    /// Initialize a VersionMap with the given capacity. Note that the capacity is how often insert can be called, not
    /// how many different keys are currently used, as values will remain in the backing store even if a new value is
    /// added with the same key. Also note that the entire capacity is allocated, so don't give it a capacity much
    /// higher than you expect to need.
    /// 
    /// The envisioned use case involves occasionally recycling the entire map when more capacity is required, but
    /// this is left to the application.
    pub fn new(capacity: usize) -> Self {
        Self {
            map: Arc::new(HashMap::new()),
            version: Arc::new(AtomicU64::new(0)),
            vec: AppendOnlyArcVec::new(capacity)
        }
    }

    /// Returns a clone of the VersionMap, referring to the same backing store. This is cheap, as it only involves 
    /// cloning Arc's and the current version.
    pub fn view(&self) -> VersionMapView<K, V>
    {
        VersionMapView {
            map: self.map.clone(),
            current: self.version.load(atomic::Ordering::Acquire),
            version: self.version.clone(),
            vec: self.vec.view()
        }
    }

    /// Increments the version and inserts the value. Note that the previous value will not be dropped and remains 
    /// accessible by outdated views at the same index in the backing store. If a previous value exists, a reference
    /// to it will be returned, otherwise this function returns None. If the backing store has run out of capacity, a
    /// CapacityError is raised.
    /// 
    /// Note that this function clones the values of the previous map, which can be expensive when the map is large.
    /// For bulk inserts, use [`extend`](#method.extend). However, this prevents views form always having to clone. 
    /// This map is designed for a write-rarely, read-often workflows, so views are expected to be created more often 
    /// than calls to this function. Previous maps will be deallocated when no more views reference them.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<&V>, CapacityError>
    where
        K: Eq + Hash + Clone
    {
        let mut new_map = HashMap::new();
        new_map.clone_from(&self.map);
        self.version.fetch_add(1, atomic::Ordering::AcqRel);
        let index = self.vec.push(value)?;
        let previous = new_map.insert(key, index);
        self.map = Arc::new(new_map);
        Ok(previous.and_then(|i| self.vec.get(i)))
    }

    pub fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iterator: I) -> Result<(), CapacityError>
    where
        K: Eq + Hash + Clone
    {
        let mut new_map = HashMap::new();
        new_map.clone_from(&self.map);
        for (key, value) in iterator.into_iter() {
            self.version.fetch_add(1, atomic::Ordering::AcqRel);
            let index = self.vec.push(value)?;
            new_map.insert(key, index);
        }
        self.map = Arc::new(new_map);
        Ok(())
    }
}

impl<K, V> VersionMapView<K, V> {
    /// Returns `true` if the current version is outdated. If outdated, this means that the values that a key refers
    /// to might have been changed. The old values will still be available, however. The only way to update a view
    /// is by getting a new one.``
    pub fn outdated(&self) -> bool {
        self.version.load(atomic::Ordering::Acquire) > self.current
    }
    
    /// Gets the value for the given key at the index known by this view. If the version is outdated, it will return 
    /// the value for the previously known index in an Err. It is up to the caller to fetch a new view, or decide to 
    /// continue using the old one. It is possible that the version has been incremented without any changes being 
    /// made, because the version is incremented before values are inserted. An identical version therefore guarantees 
    /// the current view is up to date.
    pub fn get<Q>(&self, key: &Q) -> Result<Option<&V>, Option<&V>>
    where
        K: Borrow<Q> + Eq + Hash,
        Q: Eq + Hash + ?Sized
    {
        let value = self.map.get(key).and_then(|i| {
            self.vec.get(*i)
        });

        if self.version.load(atomic::Ordering::Acquire) > self.current {
            return Err(value)
        }

        Ok(value)
    }
}

const SIZE: usize = 1000000;

mod test {
    use super::*;

    #[test]
    fn test_versionmap() {
        let mut vmap = VersionMap::<_, _>::new(SIZE+20);
        let size = SIZE;
        let iter = 10;
        let chunk = size/iter;
        for i in 0..iter {
            let r = (0..chunk).map(|k| ("asasfdjl;askdf".to_owned(), k*i));
            let inst = Instant::now();
            vmap.extend(r).unwrap();
            let end = inst.elapsed().as_secs_f64()*1000000f64;
            println!("i: {}. {} us.", i, end);
        }
        vmap.insert("basbas".to_owned(), SIZE).unwrap();

        let times = 10000;

        let mut b = 0;
        let o_view = vmap.view();
        let now = Instant::now();
        for _ in 0..times {
            b = *o_view.get("basbas").unwrap().unwrap();
        }
        let end = now.elapsed().as_secs_f64()*1000000f64/(times as f64);

        println!("{}: {} us.", b, end);
    }

}