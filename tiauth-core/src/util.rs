use base64::{engine::general_purpose as b64, Engine as _};
use rand::{rngs::StdRng, Rng};

pub fn nonce_384(rng: &mut StdRng) -> String {
    let mut data = vec![0u8; 48];

    rng.fill(data.as_mut_slice());

    b64::URL_SAFE_NO_PAD.encode(data.as_mut_slice())
}
