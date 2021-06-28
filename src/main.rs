#[tokio::main]
async fn main() {
    tiauth::run_server().await;
}