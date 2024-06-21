use std::collections::HashMap;
use rmpv;

use rmp_serde::{encode, decode};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Debug)]
struct Lazy<T> 
    where T: Serialize + DeserializeOwned
{
    bytes: Option<Vec<u8>>,
    inner: Option<T>
}

impl<T> Lazy<T> 
    where T: Serialize + DeserializeOwned
{
    fn new() -> Self {
        Lazy {
            bytes: None,
            inner: None,
        }
    }

    fn from_inner(inner: T) -> Self {
        Lazy {
            bytes: None,
            inner: Some(inner)
        }
    }

    fn inner<'a>(&'a mut self) -> &'a T {
        if let Some(bytes) = self.bytes.take() {
            let inner: T = rmp_serde::decode::from_slice(&bytes).unwrap();
            self.inner = Some(inner);
            
            self.inner()
        } else if let Some(inner) = &self.inner {
            inner
        } else {
            panic!("No data available!")
        }
    }
}

impl<'de, T> Deserialize<'de> for Lazy<T>
where
    T: Serialize + DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LazyVisitor<T>
        where
            T: Serialize + DeserializeOwned,
        {
            _marker: PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for LazyVisitor<T>
        where
            T: Serialize + DeserializeOwned,
        {
            type Value = Lazy<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array or a map")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Lazy {
                    bytes: Some(v.to_vec()),
                    inner: None,
                })
            }

            // fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            // where
            //     A: SeqAccess<'de>,
            // {
            //     let bytes: Vec<u8> = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
            //     Ok(Lazy {
            //         bytes: Some(bytes),
            //         inner: None,
            //     })
            // }

            // fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            // where
            //     A: MapAccess<'de>,
            // {
            //     let bytes: Vec<u8> = map.next_value()?;
            //     Ok(Lazy {
            //         bytes: Some(bytes),
            //         inner: None,
            //     })
            // }
        }

        deserializer.deserialize_bytes(LazyVisitor { _marker: PhantomData })
    }
}

impl<T> Serialize for Lazy<T> 
    where T: Serialize + DeserializeOwned
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(data) = &self.bytes {
            serializer.serialize_bytes(data)
        } else if let Some(inner) = &self.inner {
            inner.serialize(serializer)
        } else {
            panic!("Contains no data!")
        }
    }
}

#[derive(Deserialize, Serialize)]
struct User {
    user_id: String,
    password_file: String,
    claims: Lazy<Claims>,
}

// Assuming Claims is another struct you want to deserialize lazily.
#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    f: String
}



#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn do_encode() {
        let claims = Claims {
            f: "hi".to_owned()
        };

        let lazy_claims = Lazy::from_inner(claims);
        let user = User {
            user_id: "abc".to_owned(),
            password_file: "hi".to_owned(),
            claims: lazy_claims
        };
        // let user_j = serde_json::to_string(&user).unwrap();
        // println!("{}", user_j);

        // let user: User = serde_json::from_str(&user_j).unwrap();

        let user_bytes = rmp_serde::encode::to_vec_named(&user).unwrap();

        let mut user: User = rmp_serde::decode::from_slice(&user_bytes).unwrap();
    
        // When you need to access the claims:
        let de_claims = user.claims.inner();

        println!("{:?}", de_claims);

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