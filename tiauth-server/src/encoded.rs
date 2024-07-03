use core::fmt;
use std::{fmt::Display, marker::PhantomData};
use base64::{engine::general_purpose as b64, DecodeError, Engine as _};
use serde::{de::{self, Visitor}, Deserialize, Deserializer, Serialize, Serializer};
use tiauth_core::{ByteOwned, ByteSerial};

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
pub struct ByteEncoded<E, T> 
    where T: ByteSerial, E: Encoding
{
    phantom: PhantomData<E>,
    bytes: ByteOwned<T>
}

impl<E, T> ByteEncoded<E, T>
    where T: ByteSerial, E: Encoding
{
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            phantom: PhantomData,
            bytes: ByteOwned::new(bytes)
        }
    }

    pub fn as_byte_owned(&self) -> &ByteOwned<T> {
        &self.bytes
    }
}

#[derive(Deserialize, Debug)]
#[serde(bound(serialize = "T: ByteSerial", deserialize = "T: ByteSerial"))]
pub struct B64UrlEncoded<T: ByteSerial>(ByteEncoded<Base64UrlEncoding, T>);

impl<T> B64UrlEncoded<T>
    where T: ByteSerial
{
    pub fn as_byte_owned(&self) -> &ByteOwned<T> {
        &self.0.bytes
    }
}

impl<'de, E, T> Deserialize<'de> for ByteEncoded<E, T>
where
    T: ByteSerial, E: Encoding
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
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

        impl<'de, E, T> Visitor<'de> for EncodedVisitor<E, T>
        where
            T: ByteSerial, E: Encoding
        {
            type Value = ByteEncoded<E, T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array or str")
            }

            fn visit_str<Error>(self, v: &str) -> Result<Self::Value, Error>
            where
                Error: de::Error,
            {
                match E::decode(v) {
                    Ok(data) => Ok(Self::Value::new(data)),
                    Err(e) => Err(Error::custom(format!("unable to decode due to error in decoder: {}", e))),
                }
            }

            fn visit_byte_buf<Error>(self, v: Vec<u8>) -> Result<Self::Value, Error>
            where
                Error: de::Error,
            {
                Ok(Self::Value::new(v))
            }

            fn visit_bytes<Error>(self, v: &[u8]) -> Result<Self::Value, Error>
            where
                Error: de::Error,
            {
                Ok(Self::Value::new(v.to_vec()))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(EncodedVisitor::new())
        } else {
            deserializer.deserialize_byte_buf(EncodedVisitor::new())
        }
    }
}

impl<E, T> Serialize for ByteEncoded<E, T>
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