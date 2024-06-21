use std::collections::HashMap;
use rmpv;
use base64::{engine::general_purpose as b64, Engine as _};
use rmp_serde::{encode, decode};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use std::fmt::{self, Debug};
use std::marker::PhantomData;
use std::sync::Arc;
use serde_json::Value;

struct Lazy<T> 
{
    bytes: Option<Vec<u8>>,
    inner: Option<T>
}

impl<T> Debug for Lazy<T> 
    where T: Debug
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(inner) = &self.inner {
            write!(f, "{:?}", inner)?;
        } else if let Some(bytes) = &self.bytes {
            f.debug_struct("Lazy").field("bytes", bytes).finish()?;
        }

        Ok(())
    }
}

impl<T> Lazy<T> 
    where T: DeserializeOwned
{
    fn from_bytes(bytes: Vec<u8>) -> Self {
        Lazy {
            bytes: Some(bytes),
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
            panic!("Lazy structure is invalid, it contains no data!")
        }
    }

    fn take(self) -> T {
        if let Some(bytes) = self.bytes {
            let inner: T = rmp_serde::decode::from_slice(&bytes).unwrap();
            inner
        } else if let Some(inner) = self.inner {
            inner
        } else {
            panic!("Lazy structure is invalid, it contains no data!")
        }
    }
}

impl<'de, T> Deserialize<'de> for Lazy<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LazyVisitor<T>
        where
            T: DeserializeOwned,
        {
            _marker: PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for LazyVisitor<T>
        where
            T: DeserializeOwned,
        {
            type Value = Lazy<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array or str")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match b64::URL_SAFE_NO_PAD.decode(v) {
                    Ok(data) => Ok(Lazy::from_bytes(data)),
                    Err(_) => Err(E::custom("not valid base64url without padding"))
                }
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where E: de::Error
            {
                Ok(Lazy::from_bytes(v))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where E: de::Error
            {
                Ok(Lazy::from_bytes(v.to_vec()))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(LazyVisitor { _marker: PhantomData })
        } else {
            deserializer.deserialize_byte_buf(LazyVisitor { _marker: PhantomData })
        }
    }
}

impl<T> Serialize for Lazy<T> 
    where T: Serialize
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(data) = &self.bytes {
            if serializer.is_human_readable() {
                let s = b64::URL_SAFE_NO_PAD.encode(data);
                serializer.serialize_str(&s)
            } else {
                serializer.serialize_bytes(data)
            }
        } else if let Some(inner) = &self.inner {
            let data = rmp_serde::encode::to_vec_named(inner).unwrap();
            
            if serializer.is_human_readable() {
                let s = b64::URL_SAFE_NO_PAD.encode(data);
                serializer.serialize_str(&s)
            } else {
                serializer.serialize_bytes(&data)
            }
        } else {
            panic!("Lazy structure is invalid, it contains no data!")
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
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

trait UnwrapLazy {
    fn unwrap_lazy(self) -> Self;
}

impl<T> UnwrapLazy for Lazy<T>
    where T: DeserializeOwned
{
    fn unwrap_lazy(self) -> Self {
        Self::from_inner(self.take())
    }
}

impl UnwrapLazy for User {
    fn unwrap_lazy(self) -> Self {
        User {
            user_id: self.user_id,
            password_file: self.password_file,
            claims: self.claims.unwrap_lazy()
        }
    }
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
        println!("user:\n{:?}", user);
        let user_j = serde_json::to_string(&user).unwrap();
        println!("json repr\n{}", user_j);

        let user: User = serde_json::from_str(&user_j).unwrap();

        println!("user\n{:?}", user);

        let user_bytes = rmp_serde::encode::to_vec_named(&user).unwrap();

        println!("msgpack lossy\n{}", String::from_utf8_lossy(&user_bytes));

        let mut user: User = rmp_serde::decode::from_slice(&user_bytes).unwrap();
    
        // When you need to access the claims:
        let de_claims = user.claims.inner();

        println!("{:?}", de_claims);
    }
}