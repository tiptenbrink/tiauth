use std::time::Instant;

use tiauth_core::test::login_create_session;
use tiauth_core::test::TestState;
use tiauth_core::SessionClaims;

fn main() {
    let state = TestState::setup_test("app");
    let now = Instant::now();
    let session = login_create_session(&state, "user", "app", "pass", None, SessionClaims::All);
    let after = Instant::now();
    let time = after.duration_since(now).as_secs_f64() * 1000f64;
    println!("session:\n{:?}", session);
    println!("time: {} ms", time);
}
