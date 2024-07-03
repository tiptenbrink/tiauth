use core::fmt;
use std::{convert::Infallible, fmt::Display, marker::PhantomData};
use axum::{async_trait, extract::{rejection::{JsonRejection, MissingJsonContentType}, FromRequest, Request}};
use base64::{engine::general_purpose as b64, DecodeError, Engine as _};
use bytes::Bytes;
use serde::{de::{self, DeserializeOwned, Visitor}, Deserialize, Deserializer, Serialize, Serializer, };
use tiauth_core::{ByteOwned, BytePacked, ByteSerial, Encodable};




#[derive(Debug)]
pub struct Encoded<T: Encodable>(T);


impl<T> Encoded<T>
    where T: Encodable
{
    pub fn get(self) -> T {
        self.0
    }
    // pub fn decode(&self) -> Result<T, <T as Encodable<'_>>::Error> {
    //     T::decode(&self.string)
    // }

    // pub fn as_packed(&self) -> &BytePacked<T> {
    //     &self.bytes.as_packed()
    // }
}

impl<T> Encodable for Encoded<T>
    where T: Encodable
{
    type Error = T::Error;
    
    fn decode(encoded: &str) -> Result<Self, Self::Error> {
        Ok(Encoded(T::decode(encoded)?))
    }
    
    fn encode(&self) -> String {
        self.0.encode()
    }
}

struct EncodedVisitor<T>
where
    T: Encodable
{
    phantom: PhantomData<T>,
}

impl<T> EncodedVisitor<T>
where
    T: Encodable
{
    fn new() -> Self {
        Self {
            phantom: PhantomData
        }
    }
}

impl<'a, T> Visitor<'a> for EncodedVisitor<T>
where
    T: Encodable
{
    type Value = Encoded<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array or str")
    }

    // fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    //     where E: de::Error
    // {
        
    // }

    fn visit_str<Error>(self, v: &str) -> Result<Self::Value, Error>
    where
        Error: de::Error,
    {
        match T::decode(v) {
            Ok(inner) => Ok(Encoded(inner)),
            Err(e) => Err(Error::custom(format!("unable to decode due to error in decoder: {}", e))),
        }
    }

    // fn visit_borrowed_str<E>(self, v: &'a str) -> Result<Self::Value, E>
    //     where E: de::Error
    // {
    //     Ok(Self::Value::new(v))
    // }
    // fn visit_byte_buf<Error>(self, v: Vec<u8>) -> Result<Self::Value, Error>
    // where
    //     Error: de::Error,
    // {
    //     Ok(Self::Value::new(BytesFrom::from_vec(v)))
    // }

    // fn visit_bytes<Error>(self, v: &[u8]) -> Result<Self::Value, Error>
    //     where Error: de::Error
    // {
    //     Ok(Self::Value::new(BytesFrom::from_vec(v.to_vec())))    

    // }

    // fn visit_borrowed_bytes<Error>(self, v: &'a [u8]) -> Result<Self::Value, Error>
    //     where Error: de::Error
    // {
    //     Ok(Self::Value::new(BytesFrom::from_slice(v)))    

    // }
}

impl<'de, T> Deserialize<'de> for Encoded<T>
where
    T: Encodable
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(EncodedVisitor::new())        

        // if deserializer.is_human_readable() {
        //     deserializer.deserialize_str(EncodedVisitor::new())
        // } else {
        //     deserializer.deserialize_bytes(EncodedVisitor::new())
        // }
    }
}

impl<T> Serialize for Encoded<T>
where
    T: Encodable,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.encode())
        // if serializer.is_human_readable() {
        //     let s = E::encode(&self.bytes.as_packed().as_bytes());
        //     serializer.serialize_str(&s)
        // } else {
        //     serializer.serialize_bytes(&self.bytes.as_packed().as_bytes())
        // }
    }
}