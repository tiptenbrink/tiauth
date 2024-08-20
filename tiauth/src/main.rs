use std::future::IntoFuture;
use std::ops::Deref;
use std::path::PathBuf;
use std::process::abort;
use std::thread::{self, sleep};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tiauth_core::appendonly::{AppendOnlyArcVec, PushMode, ReadableVector};
use tiauth_core::crypto::load_public_key;
use tiauth_core::state_impl::AppStateImpl;
use tiauth_core::StoreAddress;
use tiauth_core::{crypto::SavedPublicKey, Application, State};
use tiauth_server::{
    router::create_router, state::GovernorServerState as GenGovernorServerState,
    state::ServerState as GenServerState,
};
use tiny_http::{Method, Response};

use tokio::sync::watch::{self, Receiver, Sender};
use tokio::sync::{broadcast, oneshot};
use tokio::{runtime, time};
use tracing::debug;
use tracing_error::ErrorLayer;
use tracing_subscriber::{prelude::*, EnvFilter};

type ServerState = GenServerState<AppStateImpl>;
type GovernorServerState = GenGovernorServerState<AppStateImpl>;

fn create_dummy_app() -> AppStateImpl {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let public_key_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAIWUw+W6ukT5D+Dm8osAgTAbeD43xtzb9GAjpJPUVnEs=
-----END PUBLIC KEY-----"
        .to_owned();
    let public_key = load_public_key(&public_key_pem).unwrap();

    let app_state = AppStateImpl::load_app_state(
        "dummy",
        StoreAddress::from_path("dummy.redb"),
        Some(public_key),
        now,
    )
    .unwrap();

    app_state
}

fn init_state() -> GovernorServerState {
    let mut state = GovernorServerState::new(32);

    //     let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    //     let public_key_pem = "-----BEGIN PUBLIC KEY-----
    // MCowBQYDK2VwAyEAIWUw+W6ukT5D+Dm8osAgTAbeD43xtzb9GAjpJPUVnEs=
    // -----END PUBLIC KEY-----"
    //         .to_owned();
    //     let public_key = load_public_key(&public_key_pem).unwrap();

    //     let app_state = AppStateImpl::load_app_state("some_app", StoreAddress::from_path("some_app.redb"), Some(public_key), now).unwrap();

    //state.load_application(app_state);

    state
}

/// The 'governor' (as opposed to admin, which is per app) allows registration and deregistration of applications. It runs as a separate tiny-http server in a single loop
/// so that we can have mutable state.
fn governor_loop(
    sender: Sender<ServerState>,
    mut state: GovernorServerState,
    mut apps_to_delete: AppendOnlyArcVec<StoreAddress, PushMode>,
    exit_receiver: broadcast::Receiver<()>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let server = tiny_http::Server::http("127.0.0.1:3001").unwrap();

    println!("Governor starting...");

    loop {
        let mut request = match server.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(rq)) => rq,
            Ok(None) => {
                if exit_receiver.is_empty() {
                    continue;
                } else {
                    break;
                }
            }
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
        } else if request_url.starts_with("/load") {
            if *request.method() != Method::Post {
                request
                    .respond(Response::from_string(
                        "Invalid method for /load: must be POST!",
                    ))
                    .unwrap();
                continue;
            }
            let mut split = request_url.strip_prefix("/load").unwrap().split('/');
            let empty = split.next();
            let app_name = split.next();

            if empty.is_none() || !empty.unwrap().is_empty() || app_name.is_none() {
                let response = Response::from_string(
                    "Failed to parse registration! Request path must be of form /load/{app_name}",
                );
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
            let public_key = match load_public_key(public_key_pem.trim()) {
                Ok(key) => key,
                Err(_) => {
                    let response = Response::from_string("Invalid public key. Is it an Ed25519 public key encoded as PEM in SubjectPublicKeyInfo format?");
                    request.respond(response.with_status_code(400)).unwrap();
                    continue;
                }
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let app_state = AppStateImpl::load_app_state(
                app_name,
                StoreAddress::from_path(format!("{}.redb", app_name)),
                Some(public_key),
                now,
            )
            .unwrap();
            state.load_application(app_state)
        } else if request_url.starts_with("/delete") {
            let mut split = request_url.strip_prefix("/delete").unwrap().split('/');
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

            if let Ok(path) = state.app_mut_blocking(app_name, |a| {
                a.active = false;

                a.store.address().clone()
            }) {
                apps_to_delete.push(path).unwrap();
            }

            // state.deregister_application(app_name).unwrap();

            // rt.block_on(async {
            //     sender.send_replace(state.readonly_state());
            // });
        }

        let ok = Response::empty(200);
        request.respond(ok).unwrap();
    }
}

async fn server(state_receiver: Receiver<ServerState>, exit_receiver: broadcast::Receiver<()>) {
    println!("Starting server...");
    loop {
        let mut exit_receiver = exit_receiver.resubscribe();
        let mut signal_receiver = state_receiver.clone();
        let state = {
            // Mark it as seen so that `new_state` doesn't immediately return.
            signal_receiver.borrow_and_update().clone()
        };
        println!("Loaded state...");
        let app = create_router(state);

        println!("Created router, starting serve...\n");
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        tokio::select! {
            _ = axum::serve(listener, app)
                .with_graceful_shutdown(new_state(signal_receiver)).into_future() => {
                println!("State changed, restarting server...");
            },
            _ = exit_receiver.recv() => {
                break;
            }
        }
    }
}

async fn new_state(mut receiver: Receiver<ServerState>) {
    if let Ok(_) = receiver.changed().await {
        println!("State changed...");
    } else {
        // This is to prevent looping constantly. Should only get occur in rare cases where the governor loop panics.
        println!("Zzzz...");
        tokio::time::sleep(Duration::MAX).await;
    }
}

fn install_tracing() {
    // We have to add the error layer (see the examples in color-eyre), so we can't just use the default init
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(EnvFilter::from_default_env())
        .with(ErrorLayer::default())
        .init();
}

fn main() {
    install_tracing();

    let state = init_state();

    let (tx, rx) = watch::channel::<ServerState>(state.view());
    let (extd, mut extd_r) = broadcast::channel::<()>(2);
    let (ex_tx, ex_rx) = broadcast::channel::<()>(1);

    let apps_to_delete: AppendOnlyArcVec<StoreAddress, PushMode> = AppendOnlyArcVec::new(32);
    let delete_view = apps_to_delete.view();

    let extd_r_governor = extd.subscribe();
    let tx_governor = tx.clone();
    let handle =
        thread::spawn(|| governor_loop(tx_governor, state, apps_to_delete, extd_r_governor));

    ctrlc::set_handler(move || {
        ex_tx.send(()).unwrap();
        extd_r.blocking_recv().unwrap();
        extd_r.blocking_recv().unwrap();

        for a in delete_view.iter() {
            a.destroy()
        }

        println!("\nExiting gracefully...")
    })
    .unwrap();

    // let server = thread::spawn(|| {
    //     governor_loop(tx)
    // });

    let rt = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        server(rx, ex_rx).await;
        extd.send(()).unwrap();
    });

    handle.join().unwrap();

    extd.send(()).unwrap();
}
