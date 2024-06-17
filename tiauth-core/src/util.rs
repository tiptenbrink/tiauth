use base64::{engine::general_purpose as b64, Engine as _};
use rand::{rngs::StdRng, Rng};
use rmpv::Value;

pub fn nonce_384(rng: &mut StdRng) -> String {
    let mut data = vec![0u8; 48];

    rng.fill(data.as_mut_slice());

    b64::URL_SAFE_NO_PAD.encode(data.as_mut_slice())
}

pub fn msgpack_map<K: Into<Value>, V: Into<Value>>(map: Vec<(K, V)>) -> Value {
    let value_vec: Vec<(Value, Value)> =
        map.into_iter().map(|(k, v)| (k.into(), v.into())).collect();

    Value::Map(value_vec)
}
