use core::fmt;
use std::{fmt::Display, marker::PhantomData};
use base64::{engine::general_purpose as b64, DecodeError, Engine as _};
use serde::{de::{self, Visitor}, Deserialize, Deserializer, Serialize, Serializer};
use tiauth_core::{ByteOwned, BytePacked, ByteSerial};

trait Encoding {
    type Error: Display;

    fn decode(encoded: &str) -> Result<Vec<u8>, Self::Error>;

    fn encode(bytes: &[u8]) -> String;
}

#[derive(Debug)]
pub struct Base64UrlEncoding;

impl Encoding for Base64UrlEncoding {
    type Error = DecodeError;

    fn decode(encoded: &str) -> Result<Vec<u8>, Self::Error> {
        b64::URL_SAFE_NO_PAD.decode(encoded)
    }
    
    fn encode(bytes: &[u8]) -> String {
        b64::URL_SAFE_NO_PAD.encode(bytes)
    }
}

#[derive(Debug)]
pub enum BytesFrom<'a, T> 
    where T: ByteSerial
{
    Owned(ByteOwned<T>),
    Borrowed(&'a BytePacked<T>)
}

impl<'a, T> BytesFrom<'a, T> 
    where T: ByteSerial
{
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self::Owned(ByteOwned::new(bytes))
    }

    pub fn from_slice(slice: &'a [u8]) -> Self {
        Self::Borrowed(BytePacked::new(slice))
    }

    pub fn as_packed(&self) -> &BytePacked<T> {
        match &self {
            Self::Owned(owned) => owned.as_packed(),
            Self::Borrowed(borrowed) => borrowed
        }
    }
}

#[derive(Debug)]
pub struct ByteEncoded<'a, E, T> 
    where T: ByteSerial, E: Encoding
{
    phantom: PhantomData<E>,
    bytes: BytesFrom<'a, T>
}

impl<'a, E, T> ByteEncoded<'a, E, T>
    where T: ByteSerial, E: Encoding
{
    fn new(bytes: BytesFrom<'a, T>) -> Self {
        Self {
            phantom: PhantomData,
            bytes
        }
    }

    pub fn as_packed(&self) -> &BytePacked<T> {
        &self.bytes.as_packed()
    }
}



#[derive(Deserialize, Debug)]
#[serde(transparent)]
#[serde(bound(serialize = "T: ByteSerial", deserialize = "T: ByteSerial"))]
pub struct B64UrlEncoded<'a, T: ByteSerial + 'static> {
    #[serde(borrow)]
    encoded: ByteEncoded<'a, Base64UrlEncoding, T>
}

// impl<T> B64UrlEncoded<T>
//     where T: ByteSerial
// {
//     pub fn as_byte_owned(&self) -> &ByteOwned<T> {
//         &self.0.bytes
//     }
// }

struct EncodedVisitor<E, T>
where
    T: ByteSerial, E: Encoding
{
    phantom_decoder: PhantomData<E>,
    phantom_type: PhantomData<T>,
}

impl<E, T> EncodedVisitor<E, T>
where
    T: ByteSerial, E: Encoding
{
    fn new() -> Self {
        Self {
            phantom_decoder: PhantomData, phantom_type: PhantomData
        }
    }
}

impl<'a, E, T> Visitor<'a> for EncodedVisitor<E, T>
where
    T: ByteSerial + 'a, E: Encoding
{
    type Value = ByteEncoded<'a, E, T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array or str")
    }

    fn visit_str<Error>(self, v: &str) -> Result<Self::Value, Error>
    where
        Error: de::Error,
    {
        match E::decode(v) {
            Ok(data) => Ok(Self::Value::new(BytesFrom::from_vec(data))),
            Err(e) => Err(Error::custom(format!("unable to decode due to error in decoder: {}", e))),
        }
    }

    fn visit_byte_buf<Error>(self, v: Vec<u8>) -> Result<Self::Value, Error>
    where
        Error: de::Error,
    {
        Ok(Self::Value::new(BytesFrom::from_vec(v)))
    }

    fn visit_bytes<Error>(self, v: &[u8]) -> Result<Self::Value, Error>
        where Error: de::Error
    {
        Ok(Self::Value::new(BytesFrom::from_vec(v.to_vec())))    

    }

    fn visit_borrowed_bytes<Error>(self, v: &'a [u8]) -> Result<Self::Value, Error>
        where Error: de::Error
    {
        Ok(Self::Value::new(BytesFrom::from_slice(v)))    

    }
}

impl<'de: 'a, 'a, E, T> Deserialize<'de> for ByteEncoded<'a, E, T>
where
    T: ByteSerial + 'de, E: Encoding
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(EncodedVisitor::new())
        } else {
            deserializer.deserialize_bytes(EncodedVisitor::new())
        }
    }
}

impl<'a, E, T> Serialize for ByteEncoded<'a, E, T>
where
    T: ByteSerial, E: Encoding,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let s = E::encode(&self.bytes.as_packed().as_bytes());
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_bytes(&self.bytes.as_packed().as_bytes())
        }
    }
}