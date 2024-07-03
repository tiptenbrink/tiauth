#![allow(dead_code)]
#![allow(unused_variables)]

use criterion::{criterion_group, criterion_main, Criterion};
use tiauth_core::test::TestState;
// use tiauth_core::test::{big_claims, test_lazy_claims, test_zero_vec, TestState};

pub fn criterion_benchmark(c: &mut Criterion) {
    let state = TestState::setup_test(vec!["app"]);
    // let (zmap_vec, claims) = big_claims();

    // c.bench_function("test_zero_vec", |b| {
    //     b.iter(|| test_zero_vec(&state, "app", zmap_vec.clone()))
    // });
    // c.bench_function("test_lazy_claims", |b| {
    //     b.iter(|| test_lazy_claims(&state, "app", claims.clone()))
    // });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
