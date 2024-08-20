use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// #[tokio::main]
// async fn main() {
//     // let client = reqwest::Client::new();

//     // let application = "some_app".to_owned();
//     // let user_id = "abc".to_owned();

//     // let password = "my_password".to_owned();

//     // let (request, state) = client_register(&password).unwrap();

//     // let req = PakeRequest {
//     //     application: application.clone(),
//     //     user_id,
//     //     request
//     // };

//     // let res = client.post("http://localhost:3000/register/start")
//     //     .json(&req)
//     //     .send()
//     //     .await.unwrap();

//     // println!("{:?}", res);
//     // let PakeResponse { response, nonce } = res.json().await.unwrap();
//     // println!("response {:?}\nnonce: {:?}", response, nonce);

//     // let request = client_register_finish(&state, &password, &response).unwrap();

//     // let req = PakeFinishRequest { application: application.clone(), request, nonce };

//     // let res = client.post("http://localhost:3000/register/finish")
//     //     .json(&req)
//     //     .send()
//     //     .await.unwrap();

//     // println!("{:?}", res);
// }

// const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
// MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
// DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
// -----END PRIVATE KEY-----";

use sha2::{Digest, Sha256, Sha512};

fn main() {
    // let key = load_key(key_pem).unwrap();

    // let value = Test {
    //     int: 42,
    //     string: "hello world".to_string(),
    //     claims: HashMap::from_iter(vec![("some".to_owned(), "other".as_bytes().to_vec())]),
    // };

    // let bytes = rkyv::to_bytes::<_, 256>(&value).unwrap();

    // sign_data(&key, &bytes);

    // let archived = unsafe { rkyv::archived_root::<Test>(&bytes[..]) };

    // // archived.claims.

    // let deserialized: Test = archived.deserialize(&mut rkyv::Infallible).unwrap();
    let mut base_secret = [0u8; 32];
    StdRng::from_entropy().fill_bytes(&mut base_secret);
    println!("{:?}", base_secret);
    // Up to a month ago
    let time = (StdRng::from_entropy().next_u32() % 2500000) as u64;
    let start = SystemTime::now()
        .checked_sub(Duration::from_secs(time))
        .unwrap();

    let mut b: HashMap<String, [u8; 32]> = HashMap::new();

    let mut hasher = Sha256::new();

    hasher.update(b"some_app");
    hasher.update(&base_secret);

    let seed: [u8; 32] = hasher.finalize().into();

    b.insert("some_app".to_owned(), seed);

    //let seed = base_secret.clone();
    let instant = Instant::now();

    let seed = b.get("some_app").unwrap().clone();

    let rng = ChaCha20Rng::from_seed(seed);
    let ten_minutes_passed = SystemTime::now().duration_since(start).unwrap().as_secs() / 600;
    let mut loop_rng = rng.clone();
    loop_rng.set_stream(ten_minutes_passed);
    let mut new_key = [0u8; 32];
    loop_rng.fill_bytes(&mut new_key);
    let dur1 = Instant::now().duration_since(instant).as_secs_f64() * 1000f64;
    println!("took {} ms", dur1);
    println!("{:?}", new_key);
}
