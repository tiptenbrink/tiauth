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

use std::time::Instant;

use lazy_borink::Lazy;
use openssl::pkey::{Id, PKey};
use openssl::pkey_ctx::PkeyCtx;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tiauth_app::{create_set_claims_proof, ProofBase};
use tiauth_core::{api::Claims, crypto::load_key};

fn main() {
    let key = "-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
-----END PRIVATE KEY-----";
    
    let mut proofs = Vec::with_capacity(1000);
    let mut rng = StdRng::from_entropy();
    let mut cl_claims: Vec<u8> = Vec::with_capacity(100000);
    for i in 0..10 {
        let v = rng.next_u32();
        let vu = (v % 8) as u8;
        cl_claims.push(vu);
    }

    let openssl_ed448 = PKey::private_key_from_pem(key.as_bytes()).unwrap();
    let key_b = openssl_ed448.raw_private_key().unwrap();
    let know = Instant::now();
    let pkey2 = PKey::private_key_from_raw_bytes(&key_b, Id::ED448).unwrap();
    let pkey2 = PKey::private_key_from_pem(key.as_bytes()).unwrap();
    let know2 = Instant::now();
    println!("load_key {} ms.", know2.duration_since(know).as_secs_f32()*1000f32);
    println!("{:?}", pkey2.private_key_to_pem_pkcs8().unwrap());
    let cl_claims: Lazy<Claims> = Lazy::from_bytes(cl_claims);
    let nowm1 = Instant::now();
    let mut claims: Lazy<Claims> = Claims::new(vec![("my_claim", "is_cool")]).into();
    let claim_bytes = claims.bytes().to_vec();
    let nowm2 = Instant::now();
    let new_claims = claims.clone();
    let now = Instant::now();
    let proof_base = ProofBase::new("some_app", key);
    let now2 = Instant::now();
    //let cl_claims = new_claims.clone();
    let now3 = Instant::now();
    let proof = create_set_claims_proof(proof_base, "abc7", cl_claims);
    proofs.push(proof);
    
    println!("claims {} ms.", nowm2.duration_since(nowm1).as_secs_f32()*1000f32);
    println!("base {} ms.", now2.duration_since(now).as_secs_f32()*1000f32);
    println!("claims {} ms.", now3.duration_since(now2).as_secs_f32()*1000f32);
    let proofs = format!("{:?}", proofs);
    println!("{}...", &proofs[0..15]);
    println!("{:?}", claim_bytes);
}
