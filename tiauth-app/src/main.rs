#[tokio::main]
async fn main() {
    // let client = reqwest::Client::new();

    // let application = "some_app".to_owned();
    // let user_id = "abc".to_owned();

    // let password = "my_password".to_owned();

    // let (request, state) = client_register(&password).unwrap();

    // let req = PakeRequest {
    //     application: application.clone(),
    //     user_id,
    //     request
    // };

    // let res = client.post("http://localhost:3000/register/start")
    //     .json(&req)
    //     .send()
    //     .await.unwrap();

    // println!("{:?}", res);
    // let PakeResponse { response, nonce } = res.json().await.unwrap();
    // println!("response {:?}\nnonce: {:?}", response, nonce);

    // let request = client_register_finish(&state, &password, &response).unwrap();

    // let req = PakeFinishRequest { application: application.clone(), request, nonce };

    // let res = client.post("http://localhost:3000/register/finish")
    //     .json(&req)
    //     .send()
    //     .await.unwrap();

    // println!("{:?}", res);
}
