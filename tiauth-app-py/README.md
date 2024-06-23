### Building

Install `maturin` globally (see [instructions](https://www.maturin.rs/installation), I recommend using `cargo binstall maturin`). 

Next, activate your virtual environment with the Python version you want to build and test with and run:

`maturin develop`

This will generate an `.so` file and populate the `tiauth_app_py._internal` module, making the functions in `python/tiauth_app_py/app.py` work.

### Performance

Running `create_set_claims_proof()` on an i7-8750H (April 2018 laptop CPU) on Linux, takes about 1.0 ms (in a hot loop, doing the operation 1000 times). In Rust, this is about 0.8-0.9 ms, but JavaScript reaches similar performance as Rust.

```python
proof = create_set_claims_proof(application, private, "abc7", {"my_claim": "is_cool"})
```