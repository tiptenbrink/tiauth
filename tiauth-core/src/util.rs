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

pub fn cursor_slice<'a>(bytes: &'a [u8], cursor: &mut Cursor<&[u8]>, len: u32) -> &'a [u8] {
    let start = cursor.position() as usize;
    let end = start + (len as usize);
    cursor.set_position(end as u64);
    &bytes[start..end]
}

pub fn combine_encode(inputs: &[&[u8]], total_len: usize) -> String {
    let total_triplets = total_len / 3;

    let mut buf: Vec<u8> = vec![0; total_triplets * 4];

    buf.reserve_exact(4);
    let mut position: usize = 0;
    let mut remaining: Vec<u8> = Vec::with_capacity(3);
    for slice in inputs {
        let mut slice = *slice;
        let slice_len = slice.len();
        if slice_len == 0 {
            continue;
        }

        if !remaining.is_empty() {
            let necessary = 3 - remaining.len();
            if slice_len >= necessary {
                let slice_taken = &slice[0..necessary];
                // Remove used bytes from slice
                slice = &slice[necessary..slice_len];
                // Remaining is now always 3 bytes
                remaining.extend_from_slice(slice_taken);
                assert_eq!(remaining.len(), 3);
                let buf_slice = &mut buf[position..(position + 4)];
                b64::URL_SAFE.encode_slice(&remaining, buf_slice).unwrap();
                // 4 characters per 3 bytes
                position += 4;
                remaining = Vec::with_capacity(3);
            } else {
                // slice_len and remaining_len must be 1, otherwise it would always have enough
                assert_eq!(slice_len, 1);
                assert_eq!(remaining.len(), 1);

                remaining[1] = slice[0];
                // We can continue since we dealt with the slice
                continue;
            }
        }
        // Now remaining is always empty
        assert_eq!(remaining.len(), 0);

        let slice_len = slice.len();
        let slice_triplets = slice_len / 3;
        let slice_triplet_len = slice_triplets * 3;
        let remainder = slice_len - slice_triplet_len;
        remaining.extend_from_slice(&slice[slice_triplet_len..slice_len]);
        assert_eq!(remainder, remaining.len());

        let slice_aligned = &slice[0..slice_triplet_len];
        let buf_added = slice_triplets * 4;
        let buf_slice = &mut buf[position..(position + buf_added)];

        b64::URL_SAFE
            .encode_slice(slice_aligned, buf_slice)
            .unwrap();
        position += buf_added;
    }

    let last_part = b64::URL_SAFE_NO_PAD.encode(&remaining);
    buf.extend_from_slice(last_part.as_bytes());

    String::from_utf8(buf).unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_3_multiple() {
        let vec_1: Vec<u8> = vec![3, 9, 10, 100];
        let vec_2: Vec<u8> = vec![3, 9, 10, 100];
        let vec_3: Vec<u8> = vec![3, 9, 10, 100];

        let mut vec_combined = Vec::new();
        vec_combined.extend(&vec_1);
        vec_combined.extend(&vec_2);
        vec_combined.extend(&vec_3);

        let combined_enc = b64::URL_SAFE_NO_PAD.encode(&vec_combined);
        let combined = combine_encode(&[&vec_1, &vec_2, &vec_3], 12);

        assert_eq!(combined_enc, combined)
    }

    #[test]
    fn test_encode_not_multiple() {
        let vec_1: Vec<u8> = vec![3, 9, 10, 100, 55];
        let vec_2: Vec<u8> = vec![3, 9, 10, 100, 99];
        let vec_3: Vec<u8> = vec![3, 9, 10, 100, 22];

        let mut vec_combined = Vec::new();
        vec_combined.extend(&vec_1);
        vec_combined.extend(&vec_2);
        vec_combined.extend(&vec_3);

        let combined_enc = b64::URL_SAFE_NO_PAD.encode(&vec_combined);
        let combined = combine_encode(&[&vec_1, &vec_2, &vec_3], 15);

        assert_eq!(combined_enc, combined)
    }
}
