use std::{array, borrow::Borrow, cell::UnsafeCell, collections::HashMap, mem::MaybeUninit, sync::{atomic::{self, AtomicBool, AtomicU64, AtomicUsize}, Arc}, time::Instant, hash::Hash, fmt::Debug};

struct Indexes {
    indexes: Vec<(String, usize)>
}

impl Indexes {
    fn get(&self, s: &str) -> usize {
        let (_, v) = self.indexes.iter().find(|(k, v)| {
            k.as_str() == s
        }).unwrap();

        *v
    }
}

struct Vector<T, const N: usize> {
    index: usize,
    elements: Arc<[Element<T>; N]>
}

#[derive(Clone)]
struct VectorView<T, const N: usize> {
    elements: Arc<[Element<T>; N]>
}

impl<T, const N: usize> VectorView<T, N> {
    fn get(&self, i: usize) -> Option<&T> {
        if self.elements[i].stored.load(atomic::Ordering::Acquire) {
            let value = unsafe { (*self.elements[i].value.get()).assume_init_ref() };
            return Some(value);
        }

        None
    }
}

struct Element<T> {
    value: UnsafeCell<MaybeUninit<T>>,
    stored: AtomicBool,
}

impl<T> Drop for Element<T> {
    fn drop(&mut self) {
        if self.stored.load(atomic::Ordering::Acquire) {
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

impl<T> Element<T> {
    fn new() -> Self {
        Self {
            value: UnsafeCell::new(MaybeUninit::uninit()),
            stored: AtomicBool::new(false)
        }
    }
}

impl<T, const N: usize> Vector<T, N> {
    fn new() -> Self {
        // We do the below to ensure we do not overflow the stack while creating the Vector, because otherwise we would have to first create an array on the stack
        let mut vec: Vec<Element<T>> = Vec::with_capacity(N);
        for _ in 0..N {
            vec.push(Element::new())
        }
        // We use the .ok here to avoid having to implement Debug
        let element_box: Box<[Element<T>; N]> = vec.into_boxed_slice().try_into().ok().unwrap();
        
        Self {
            index: 0,
            elements: Arc::from(element_box)
        }
    }

    fn view(&self) -> VectorView<T, N> {
        VectorView {
            elements: self.elements.clone()
        }
    }

    fn push(&mut self, value: T) -> usize {
        let i = self.index;
        self.index += 1;
        unsafe { self.elements[i].value.get().write(MaybeUninit::new(value)) }
        self.elements[i].stored.store(true, atomic::Ordering::Release);
        i
    }
}

struct VersionMap<K, V, const N: usize> {
    map: HashMap<K, usize>,
    version: Arc<AtomicU64>,
    vec: Vector<V, N>
}

#[derive(Clone)]
struct VersionMapView<K, V, const N: usize> {
    map: HashMap<K, usize>,
    current: u64,
    version: Arc<AtomicU64>,
    vec: VectorView<V, N>
}

impl<K, V, const N: usize> VersionMap<K, V, N> {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            version: Arc::new(AtomicU64::new(0)),
            vec: Vector::new()
        }
    }

    fn view(&self) -> VersionMapView<K, V, N> 
        where K: Clone
    {
        VersionMapView {
            map: self.map.clone(),
            current: self.version.load(atomic::Ordering::Acquire),
            version: self.version.clone(),
            vec: self.vec.view()
        }
    }

    fn insert(&mut self, key: K, value: V) 
    where
        K: Eq + Hash
    {
        self.version.fetch_add(1, atomic::Ordering::AcqRel);
        let index = self.vec.push(value);
        self.map.insert(key, index);
    }
}

#[derive(Debug)]
struct OutdatedError;

impl<K, V, const N: usize> VersionMapView<K, V, N> {
    fn get<Q>(&self, key: &Q) -> Result<Option<&V>, OutdatedError>
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

struct SmallMap<K, V, const N: usize> {
    elements: Arc<[Element<(K, V)>; N]>
}

#[derive(Clone)]
struct SmallMapView<K, V, const N: usize> {
    elements: Arc<[Element<(K, V)>; N]>
}

impl<K, V, const N: usize> SmallMapView<K, V, N> {
    fn get<Q>(&self, key: &Q) -> Option<&V> 
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized
    {
        for e in self.elements.iter() {
            if e.stored.load(atomic::Ordering::Acquire) {
                let (element_key, value) = unsafe { (*e.value.get()).assume_init_ref() };
                if element_key.borrow() == key {
                    return Some(value);
                }
            }
        }

        None
    }
}

impl<K, V, const N: usize> SmallMap<K, V, N> {
    fn new() -> Self {
        Self {
            elements: Arc::new(array::from_fn(|_| Element::new()))
        }
    }

    fn view(&self) -> SmallMapView<K, V, N> {
        SmallMapView {
            elements: self.elements.clone()
        }
    }

    fn insert(&mut self, key: K, value: V) -> usize 
    where
        K: Eq
    {
        let mut first_empty = None;
        for (i, e) in self.elements.iter().enumerate() {
            if e.stored.load(atomic::Ordering::Acquire) {
                let (element_key, value) = unsafe { (*e.value.get()).assume_init_ref() };
                if element_key.borrow() == &key {
                    panic!("Key already exists!")
                }
            } else if first_empty.is_none() {
                first_empty = Some(i)
            }
        }

        if let Some(i) = first_empty {
            unsafe { self.elements[i].value.get().write(MaybeUninit::new((key, value))) }
            self.elements[i].stored.store(true, atomic::Ordering::Release);
            i
        } else {
            panic!("No empty space in map!")
        }
    }
}

const SIZE: usize = 5000;

fn main() {
    println!("{}", "hi");
    let mut lmap: HashMap<String, usize> = HashMap::new();
    let mut vmap = VersionMap::<_, _, SIZE>::new();
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
    let now = Instant::now();
    for i in 0..times {
        b = *lmap.get("basbas").unwrap();
    }
    let end = now.elapsed().as_secs_f64()*1000000f64/(times as f64);

    println!("{}: {} us.", b, end);

    let mut b = 0;
    let o_view = vmap.view();
    let now = Instant::now();
    for i in 0..times {
        b = *o_view.get("basbas").unwrap().unwrap();
    }
    let end = now.elapsed().as_secs_f64()*1000000f64/(times as f64);

    println!("{}: {} us.", b, end);
}

fn main_smap() {
    let mut l = Indexes { indexes: Vec::new() };
    let mut lmap: HashMap<String, usize> = HashMap::new();
    let mut smap = SmallMap::<_, _, SIZE>::new();
    let size = SIZE;
    let mut o_loc = 0;
    for i in 0..size {
        if i == size-2 {
            l.indexes.push(("basbas".to_owned(), i));
            lmap.insert("basbas".to_owned(), i);
            smap.insert("basbas".to_owned(), i);
        } else {
            l.indexes.push(("abcasdfasdfaeawyawanawrawrh".to_owned(), i));
            lmap.insert(format!("abcasdfasdfaeawyawanawrawrh{}", i), i);
            smap.insert(format!("abcasdfasdfaeawyawanawrawrh{}", i), i);
        }   
    }
    let times = 10000;

    let mut b = 0;
    let now = Instant::now();
    for i in 0..times {
        b = l.get("basbas");
    }
    
    let end = now.elapsed().as_secs_f64()*1000000f64/(times as f64);

    
    println!("{}: {} us.", b, end);
    let mut b = 0;
    let now = Instant::now();
    for i in 0..times {
        b = *lmap.get("basbas").unwrap();
    }
    let end = now.elapsed().as_secs_f64()*1000000f64/(times as f64);

    println!("{}: {} us.", b, end);

    let mut b = 0;
    let o_view = smap.view();
    let now = Instant::now();
    for i in 0..times {
        b = *o_view.get("basbas").unwrap();
    }
    let end = now.elapsed().as_secs_f64()*1000000f64/(times as f64);

    println!("{}: {} us.", b, end);
}