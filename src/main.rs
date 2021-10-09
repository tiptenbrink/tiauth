#[tokio::main]
async fn main() {
    tiauth::prepare_server().await;
    tiauth::run_server().await;
}