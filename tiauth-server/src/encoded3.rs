use core::fmt;
use std::{convert::Infallible, fmt::Display, marker::PhantomData};
use axum::{async_trait, extract::{rejection::{JsonRejection, MissingJsonContentType}, FromRequest, Request}};
use base64::{engine::general_purpose as b64, DecodeError, Engine as _};
use bytes::Bytes;
use serde::{de::{self, DeserializeOwned, Visitor}, Deserialize, Deserializer, Serialize, Serializer, };
use tiauth_core::{ByteOwned, BytePacked, ByteSerial, Encodable, EncodableOwned};




#[derive(Debug)]
pub struct StrEncoded<'a, T> 
    where T: EncodableOwned
{
    phantom: PhantomData<T>,
    string: &'a str
}

impl<'a, T> StrEncoded<'a, T>
    where T: EncodableOwned
{
    fn new(string: &'a str) -> Self {
        Self {
            phantom: PhantomData,
            string
        }
    }

    pub fn decode(&self) -> Result<T, <T as Encodable<'_>>::Error> {
        T::decode(&self.string)
    }

    // pub fn as_packed(&self) -> &BytePacked<T> {
    //     &self.bytes.as_packed()
    // }
}

impl<'a, T> Encodable<'a> for StrEncoded<'a, T>
    where T: EncodableOwned
{
    type Error = Infallible;
    
    fn decode(encoded: &'a str) -> Result<Self, Self::Error> where Self: Sized {
        Ok(Self::new(encoded))
    }
    
    fn encode(&self) -> String {
        self.string.to_owned()
    }
}

struct EncodedVisitor<T>
where
    T: EncodableOwned
{
    phantom: PhantomData<T>,
}

impl<T> EncodedVisitor<T>
where
    T: EncodableOwned
{
    fn new() -> Self {
        Self {
            phantom: PhantomData
        }
    }
}

impl<'a, T> Visitor<'a> for EncodedVisitor<T>
where
    T: EncodableOwned
{
    type Value = StrEncoded<'a, T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array or str")
    }

    // fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    //     where E: de::Error
    // {
        
    // }

    // fn visit_str<Error>(self, v: &str) -> Result<Self::Value, Error>
    // where
    //     Error: de::Error,
    // {
    //     match E::decode(v) {
    //         Ok(data) => Ok(Self::Value::new(BytesFrom::from_vec(data))),
    //         Err(e) => Err(Error::custom(format!("unable to decode due to error in decoder: {}", e))),
    //     }
    // }

    fn visit_borrowed_str<E>(self, v: &'a str) -> Result<Self::Value, E>
        where E: de::Error
    {
        Ok(Self::Value::new(v))
    }
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

impl<'de: 'a, 'a, T> Deserialize<'de> for StrEncoded<'a, T>
where
    T: EncodableOwned
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

impl<'a, T> Serialize for StrEncoded<'a, T>
where
    T: EncodableOwned,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.string)
        // if serializer.is_human_readable() {
        //     let s = E::encode(&self.bytes.as_packed().as_bytes());
        //     serializer.serialize_str(&s)
        // } else {
        //     serializer.serialize_bytes(&self.bytes.as_packed().as_bytes())
        // }
    }
}



#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

#[async_trait]
impl<'de, T, S> FromRequest<S> for Json<T>
where
    T: Deserialize<'de>,
    S: Send + Sync,
{
    type Rejection = JsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if json_content_type(req.headers()) {
            let bytes = Bytes::from_request(req, state).await?;
            Self::from_bytes(&bytes)
        } else {
            let a = MissingJsonContentType;
            Err(MissingJsonContentType.into())
        }
    }
}

fn json_content_type(headers: &HeaderMap) -> bool {
    let content_type = if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        content_type
    } else {
        return false;
    };

    let content_type = if let Ok(content_type) = content_type.to_str() {
        content_type
    } else {
        return false;
    };

    let mime = if let Ok(mime) = content_type.parse::<mime::Mime>() {
        mime
    } else {
        return false;
    };

    let is_json_content_type = mime.type_() == "application"
        && (mime.subtype() == "json" || mime.suffix().map_or(false, |name| name == "json"));

    is_json_content_type
}

impl<'de, T> Json<T>
where
    T: Deserialize<'de>,
{
    /// Construct a `Json<T>` from a byte slice. Most users should prefer to use the `FromRequest` impl
    /// but special cases may require first extracting a `Request` into `Bytes` then optionally
    /// constructing a `Json<T>`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JsonRejection> {
        let deserializer = &mut serde_json::Deserializer::from_slice(bytes);

        let value = match serde_path_to_error::deserialize(deserializer) {
            Ok(value) => value,
            Err(err) => {
                let rejection = match err.inner().classify() {
                    serde_json::error::Category::Data => JsonDataError::from_err(err).into(),
                    serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                        JsonSyntaxError::from_err(err).into()
                    }
                    serde_json::error::Category::Io => {
                        if cfg!(debug_assertions) {
                            // we don't use `serde_json::from_reader` and instead always buffer
                            // bodies first, so we shouldn't encounter any IO errors
                            unreachable!()
                        } else {
                            JsonSyntaxError::from_err(err).into()
                        }
                    }
                };
                return Err(rejection);
            }
        };

        Ok(Json(value))
    }
}