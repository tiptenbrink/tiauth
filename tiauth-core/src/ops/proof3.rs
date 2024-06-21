

use std::collections::HashMap;

trait Serialization {
    fn deserialize(bytes: &[u8]) -> Self;

    fn serialize(self) -> Vec<u8>;
}

#[derive(Clone)]
struct Lazy<T> 
{
    bytes: Option<Vec<u8>>,
    inner: Option<T>
}

impl Serialization for HashMap<String, Vec<u8>> {
    fn deserialize(mut bytes: &[u8]) -> Self {
        
        let map: Self = rmp_serde::decode::from_slice(bytes).unwrap();
        
        // let mut map = Self::new();
        // let l = rmp::decode::read_map_len(&mut bytes).unwrap();

        // for _ in 0..l {
        //     let mut key = Vec::new();
        //     rmp::decode::read_str(&mut bytes, &mut key).unwrap();

        //     let v_len = rmp::decode::read_bin_len(&mut bytes).unwrap();

        //     let (src, newly_remaining) = bytes.split_at(v_len as usize);
        //     bytes = newly_remaining;
            
        //     let value = src.to_vec();

        //     map.insert(String::from_utf8(key).unwrap(), value);
        // }

        map
    }

    fn serialize(self) -> Vec<u8> {
        rmp_serde::encode::to_vec(&self).unwrap()
    }
}

struct Login {
    user_id: String,
    password_file: String,
    claims: Lazy<HashMap<String, Vec<u8>>>,
}


impl<T> Lazy<T> 
    where T: Serialization
{
    fn from_inner(inner: T) -> Self {
        Lazy {
            bytes: None,
            inner: Some(inner)
        }
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Lazy {
            bytes: Some(bytes),
            inner: None
        }
    }

    fn bytes(mut self) -> Vec<u8> {
        if let Some(bytes) = self.bytes {
            bytes
        } else if let Some(inner) = self.inner.take() {
            self.bytes = Some(inner.serialize());

            self.bytes()
        } else {
            panic!("No data available!")
        }
    }

    fn inner<'a>(&'a mut self) -> &'a T {
        if let Some(bytes) = self.bytes.take() {
            self.inner = Some(T::deserialize(&bytes));
            
            self.inner()
        } else if let Some(inner) = &self.inner {
            inner
        } else {
            panic!("No data available!")
        }
    }
}

impl<T> Serialization for Lazy<T>
    where T: Serialization
{
    fn deserialize(bytes: &[u8]) -> Self {
        Lazy::from_bytes(bytes.to_vec())
    }

    fn serialize(self) -> Vec<u8> {
        self.bytes()
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Lazy<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.bytes.is_some() {
            write!(f, "{:?}", self.bytes)?;
        } else {
            write!(f, "{:?}", self.inner)?;
        }

        Ok(())
    }
}

impl Serialization for Login {
    fn deserialize(bytes: &[u8]) -> Self {
        todo!()
    }

    fn serialize(self) -> Vec<u8> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn do_encode() {
        let mut claims = HashMap::new();
        claims.insert("cool".to_owned(), "value".to_owned().into_bytes());

        let lazy_claims = Lazy::from_inner(claims);
        let user = Login {
            user_id: "abc".to_owned(),
            password_file: "hi".to_owned(),
            claims: lazy_claims.clone()
        };
        // let user_j = serde_json::to_string(&user).unwrap();
       
        let claims_ser = lazy_claims.serialize();

        let mut claims: Lazy<HashMap<String, Vec<u8>>> = Lazy::from_bytes(claims_ser);
        println!("c {:?}", claims);
        let inner = claims.inner();
       
        // // When you need to access the claims:
        // let de_claims = user.claims.inner();

        println!("i {:?}", inner);
        println!("c {:?}", claims);

        // let u = User {
        //     user_id: "hi".to_owned(),
        //     password_file: "abc".to_owned(),
        //     claims: Claims::new(vec![("email", "abc@abc.nl")])
        // };

        // let mut enc = u.encode();

        // println!("{:?}", enc);


        // println!("{:?}", String::from_utf8_lossy(&enc));

        // let mut enc_r = enc.as_slice();

        // println!("{:?}", rmpv::decode::read_value(&mut enc_r).unwrap());
    }
}