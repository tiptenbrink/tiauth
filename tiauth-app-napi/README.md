Setup `wasm32-unknown-unknown` target if you did not do so already:

```
rustup target add wasm32-unknown-unknown
```

```
cargo build --target=wasm32-unknown-unknown --release
```