use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tiauth_core::crypto::load_public_key;
use tiauth_core::StoreAddress;
use tiauth_core::{crypto::SavedPublicKey, Application, State};
use tiauth_core::state_impl::AppStateImpl;
use tiauth_server::{router::create_router, state::{ServerState as GenServerState}, state::{GovernorServerState as GenGovernorServerState}, state::{AppStates as GenAppStates}};
use tiny_http::{Method, Response};

use tokio::runtime;
use tokio::sync::watch::{self, Receiver, Sender};

type AppStates = GenAppStates<AppStateImpl>;
type ServerState = GenServerState<AppStateImpl>;
type GovernorServerState = GenGovernorServerState<AppStateImpl>;

fn init_state() -> GovernorServerState {
    let mut state = GovernorServerState::new(8);

   
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let public_key_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAIWUw+W6ukT5D+Dm8osAgTAbeD43xtzb9GAjpJPUVnEs=
-----END PUBLIC KEY-----"
        .to_owned();
    let public_key = load_public_key(&public_key_pem).unwrap();

    let app_state = AppStateImpl::load_app_state("some_app", StoreAddress::from_path("server.redb"), Some(public_key), now).unwrap();

    state.load_application(app_state);

    state
}

/// The 'governor' (as opposed to admin, which is per app) allows registration and deregistration of applications. It runs as a separate tiny-http server in a single loop
/// so that we can have mutable state. To avoid mutexes in the state used by the main server, ServerState cannot be mutable. So updating it means recreating the entire
/// server. So when the state is updated by the governor, the axum server shuts down gracefully and restarts.
fn governor_loop(sender: Sender<AppStates>, receiver: Receiver<AppStates>, mut state: GovernorServerState) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let server = tiny_http::Server::http("127.0.0.1:3001").unwrap();

    println!("Governor starting...");

    loop {
        let mut request = match server.recv() {
            Ok(rq) => rq,
            Err(e) => {
                println!("error: {}", e);
                break;
            }
        };

        println!("Governor received request at {}...", request.url());
        let request_url = request.url().to_owned();
        if request_url == "/restart" {
            if *request.method() != Method::Post {
                request
                    .respond(
                        Response::from_string("Invalid method for /restart: must be POST!")
                            .with_status_code(400),
                    )
                    .unwrap();
                continue;
            }
            println!("Restarting...");
            rt.block_on(async {
                sender.send_replace(state.view());
            });
        } else if request_url.starts_with("/register") {
            if *request.method() != Method::Post {
                request
                    .respond(Response::from_string(
                        "Invalid method for /register: must be POST!",
                    ))
                    .unwrap();
                continue;
            }
            let mut split = request_url.strip_prefix("/register").unwrap().split('/');
            let empty = split.next();
            let app_name = split.next();

            if empty.is_none() || !empty.unwrap().is_empty() || app_name.is_none() {
                let response = Response::from_string("Failed to parse registration! Request path must be of form /register/{app_name}");
                request.respond(response.with_status_code(400)).unwrap();
                continue;
            }

            let public_key_pem = if let Some(len) = request.body_length() {
                if len > 128 {
                    let response = Response::from_string("Public key is too long to be an Ed25519 public key or trimmed length is not exactly 112 bytes.");
                    request.respond(response.with_status_code(400)).unwrap();
                    continue;
                }
                let mut content = String::new();

                if request.as_reader().read_to_string(&mut content).is_err() {
                    let response = Response::from_string("Failed to read request body.");
                    request.respond(response.with_status_code(400)).unwrap();
                    continue;
                }

                content
            } else {
                let response = Response::from_string("Unable to get request body length.");
                request.respond(response.with_status_code(400)).unwrap();
                continue;
            };

            let app_name = app_name.unwrap();

            if app_name.len() > 256 {
                let response = Response::from_string("Application name must fit in 256 bytes.");
                request.respond(response.with_status_code(400)).unwrap();
                continue;
            }

            if public_key_pem.trim().len() != 112 {
                let response = Response::from_string("Trimmed public key length is not exactly 112 bytes, so cannot be Ed25519 public key encoded as PEM in SubjectPublicKeyInfo format.");
                request.respond(response.with_status_code(400)).unwrap();
                continue;
            }
            let public_key = match SavedPublicKey::validate_pem(public_key_pem.trim()) {
                Ok(key) => key,
                Err(_) => {
                    let response = Response::from_string("Invalid public key. Is it an Ed25519 public key encoded as PEM in SubjectPublicKeyInfo format?");
                    request.respond(response.with_status_code(400)).unwrap();
                    continue;
                }
            };
            let app = Application::new(public_key, app_name);

            state.register_application(&app).unwrap();

            rt.block_on(async {
                sender.send_replace(state.readonly_state());
            });
        } else if request_url.starts_with("/deregister") {
            let mut split = request_url.strip_prefix("/deregister").unwrap().split('/');
            let empty = split.next();
            let app_name = split.next();

            if empty.is_none() || !empty.unwrap().is_empty() || app_name.is_none() {
                let response = Response::from_string("Failed to parse registration! Request path must be of form /deregister/{app_name}");
                request.respond(response.with_status_code(400)).unwrap();
                continue;
            }

            let app_name = app_name.unwrap();

            if app_name.len() > 256 {
                let response = Response::from_string("Application name must fit in 256 bytes.");
                request.respond(response.with_status_code(400)).unwrap();
                continue;
            }

            state.deregister_application(app_name).unwrap();

            rt.block_on(async {
                sender.send_replace(state.readonly_state());
            });
        }

        let ok = Response::empty(200);
        request.respond(ok).unwrap();
    }
}

fn main() {
    let state = init_state();

    let (tx, rx) = watch::channel::<ServerState>(state.readonly_state());

    let handle = thread::spawn(|| governor_loop(tx, state));

    // let server = thread::spawn(|| {
    //     governor_loop(tx)
    // });

    let rt = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        server(rx).await;
    });

    handle.join().unwrap();
}

async fn server(state_receiver: Receiver<ServerState>) {
    println!("Starting server.");
    loop {
        let mut signal_receiver = state_receiver.clone();
        let state = {
            // Mark it as seen so that `new_state` doesn't immediately return.
            signal_receiver.borrow_and_update().clone()
        };
        println!("Loaded state with apps: {:?}", state.apps());
        let app = create_router(state);

        println!("Created router, starting serve...\n");
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, app)
            .with_graceful_shutdown(new_state(signal_receiver))
            .await
            .unwrap();
    }
}

async fn new_state(mut receiver: Receiver<ServerState>) {
    receiver.changed().await.unwrap();
    println!("State changed...");
}
