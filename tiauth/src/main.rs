use tiauth_core::{crypto::SavedPublicKey, Application, State};
use tiauth_server::{router::create_router, state::ServerState};
use std::{thread};
use tokio::sync::watch::{self, Sender, Receiver};
mod governor;
use tokio::runtime;


fn init_state() -> ServerState {
    let mut state = ServerState::setup("server.redb").unwrap();

    let public_key_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAIWUw+W6ukT5D+Dm8osAgTAbeD43xtzb9GAjpJPUVnEs=
-----END PUBLIC KEY-----"
        .to_owned();

    let app = Application::new(
        SavedPublicKey::validate_pem(&public_key_pem).unwrap(),
        "some_app",
    );

    state.register_application(&app, true).unwrap();

    state
}

fn governor_loop(sender: Sender<ServerState>) {
    let state = init_state();

    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();


    let server = tiny_http::Server::http("127.0.0.1:3001").unwrap();

    loop {
        // blocks until the next request is received
        let request = match server.recv() {
            Ok(rq) => rq,
            Err(e) => { println!("error: {}", e); break }
        };

        if request.url().contains("reset") {
            rt.block_on(async {
                sender.send_replace(state.clone());
            })
        }
    }
}

fn main() {
    let state = init_state();
    
    let (tx, rx) = watch::channel::<ServerState>(state);

    let handle = thread::spawn(|| {
        governor_loop(tx)
    });

    // let server = thread::spawn(|| {
    //     governor_loop(tx)
    // });

    let rt = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        server(rx).await;
    })

}

async fn server(state_receiver: Receiver<ServerState>) {

    loop {
        let state = state_receiver.borrow().to_owned();
        let app = create_router(&state);
        
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, app)
            .with_graceful_shutdown(new_state(state_receiver))
            .await.unwrap();
    }


    // run our app with hyper, listening globally on port 3000
    
}

async fn new_state(receiver: Receiver<ServerState>) {
    receiver.has_changed()
}