use std::io::Cursor;

use base64::{engine::general_purpose as b64, Engine as _};
use rand::{rngs::StdRng, Rng};

pub fn nonce_384_bytes(rng: &mut StdRng) -> Vec<u8> {
    let mut data = vec![0u8; 48];

    rng.fill(data.as_mut_slice());

    data
}

pub fn nonce_384(rng: &mut StdRng) -> String {
    let mut data = vec![0u8; 48];

    rng.fill(data.as_mut_slice());

    b64::URL_SAFE_NO_PAD.encode(data.as_mut_slice())
}

pub fn cursor_slice<'a, 'b>(bytes: &'a [u8], cursor: &'b mut Cursor<&[u8]>, len: u32) -> &'a [u8] {
    let start = cursor.position() as usize;
    let end = start+(len as usize);
    cursor.set_position(end as u64);
    &bytes[start..end]
}