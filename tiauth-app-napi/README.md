## Building

Install `napi` globally (see [instructions](https://napi.rs/docs/introduction/getting-started#install-cli)).

```
napi build --platform --release
```

This generates an `index.js` and `index.d.ts`, as well as a `.node` file.

## Performance

Running `createSetClaimsProof()` on an i7-8750H (April 2018 laptop CPU) on Linux, takes about 0.8-0.9 ms (in a hot loop, doing the operation 1000 times). This is indistinguishable from running this directly in Rust (also 0.8-0.9 ms), so the NAPI overhead is insigificant compared to the actual cryptographic signing that happens using OpenSSL.

```js
const proof = createSetClaimsProof("some_app", key, "abc7", {"my_claim": "is_cool"})
```

For small claim objects, the difference in sign time is significant between Ed448 and Ed25519, namely 0.21 ms vs 0.038 ms. 

<!-- For big claim objects (1 MB), the difference is ~5 vs ~4 ms, much smaller than the overhead of moving the bytes to Rust. -->