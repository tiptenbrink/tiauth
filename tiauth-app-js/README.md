## Building

Setup `wasm32-unknown-unknown` target if you did not do so already:

```
rustup target add wasm32-unknown-unknown
```

```
cargo build --target=wasm32-unknown-unknown --release
wasm-bindgen ../target/wasm32-unknown-unknown/release/tiauth_app_js.wasm
```


<!-- ## Performance

Running `createSetClaimsProof()` on an i7-8750H (April 2018 laptop CPU) on Linux, takes about 0.8-0.9 ms (in a hot loop, doing the operation 1000 times). This is indistinguishable from running this directly in Rust (also 0.8-0.9 ms), so the NAPI overhead is insigificant compared to the actual cryptographic signing that happens using OpenSSL.

```js
const proof = createSetClaimsProof("some_app", key, "abc7", {"my_claim": "is_cool"})
```

For small claim objects, the difference in sign time is significant between Ed448 and Ed25519, namely 0.21 ms vs 0.038 ms. 

For big claim objects (1 MB), the difference is ~5 vs ~4 ms, much smaller than the overhead of moving the bytes to Rust. -->