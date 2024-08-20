use core::fmt;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt::Display, marker::PhantomData};

pub trait Encodable {
    type Error: Display;

    fn decode(encoded: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn encode(&self) -> String;

    fn into_encoded(self) -> Encoded<Self>
    where
        Self: Sized,
    {
        Encoded::from_encodable(self)
    }
}

/// Simple newtype that implements Serialize and Deserialize for Encodable types. This means those types don't have to
/// implement Serialize and Deserialize themselves, giving more control by allowing (de)serialization to happen only
/// through their custom Encodable implementation.
#[derive(Debug)]
pub struct Encoded<T: Encodable>(T);

impl<T> Encoded<T>
where
    T: Encodable,
{
    pub fn from_encodable(encodable: T) -> Self {
        Self(encodable)
    }

    pub fn get(self) -> T {
        self.0
    }
}

impl<T> Encodable for Encoded<T>
where
    T: Encodable,
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
    T: Encodable,
{
    phantom: PhantomData<T>,
}

impl<T> EncodedVisitor<T>
where
    T: Encodable,
{
    fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<'a, T> Visitor<'a> for EncodedVisitor<T>
where
    T: Encodable,
{
    type Value = Encoded<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array or str")
    }

    fn visit_str<Error>(self, v: &str) -> Result<Self::Value, Error>
    where
        Error: de::Error,
    {
        match T::decode(v) {
            Ok(inner) => Ok(Encoded(inner)),
            Err(e) => Err(Error::custom(format!(
                "unable to decode due to error in decoder: {}",
                e
            ))),
        }
    }
}

impl<'de, T> Deserialize<'de> for Encoded<T>
where
    T: Encodable,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(EncodedVisitor::new())
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
    }
}
