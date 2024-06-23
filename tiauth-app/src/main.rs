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
use tiauth_app::{create_set_claims_proof, ProofBase};
use tiauth_core::api::Claims;

fn main() {
    let key = "-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
-----END PRIVATE KEY-----";
    
    let mut proofs = Vec::with_capacity(1000);
    
    let mut total = 0f64;
    let mut claims: Lazy<Claims> = Claims::new(vec![("my_claim", "is_cool")]).into();
    let claim_bytes = claims.bytes().to_vec();
    let new_claims = claims.clone();
    for  _i in 0..10 {
        let now = Instant::now();
        let proof_base = ProofBase::new("some_app", key);
        let now2 = Instant::now();
        let cl_claims = new_claims.clone();
        let now3 = Instant::now();
        let proof = create_set_claims_proof(proof_base, "abc7", cl_claims);
        let after = Instant::now();
        proofs.push(proof);
        total += after.duration_since(now).as_secs_f64();
    }
    
    

    println!("Time: {} ms.", total*1000f64/10f64);
    let proofs = format!("{:?}", proofs);
    println!("{}...", &proofs[0..15]);
    println!("{:?}", claim_bytes);
}
