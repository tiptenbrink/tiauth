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


const key_pem: &'static str = "-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
-----END PRIVATE KEY-----";

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
}
