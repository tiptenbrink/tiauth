### Building

Install `maturin` globally (see [instructions](https://www.maturin.rs/installation), I recommend using `cargo binstall maturin`). 

Next, activate your virtual environment with the Python version you want to build and test with and run:

`maturin develop`

This will generate an `.so` file and populate the `tiauth_app_py._internal` module, making the functions in `python/tiauth_app_py/app.py` work.

### Performance

Below benchmarks are done using `create_set_claims_proof()` on an i7-8750H (April 2018 laptop CPU) on Linux, in a hot loop, doing the operation 1000 times and taking the average.

Loading the key can be more than 500 us, so that is why we don't load from the PEM each time.

For small claims (< 1 kB): 60 us (dominated by signing). Here, Ed448 is about an order of magnitude slower than Ed25519. 

For medium claims (~10 kB): 340 us (siging is still the largest portion here). At this point Ed448 is only about 1.5x times slower, this becomes even less for bigger claims.

For large claims (~100 kB): 2.7 ms (the overhead of sending to Rust becomes significant here).

For very large claims (~1 MB): ~38 ms (the overhead of sending to Rust now dominates). Deserialization is also a significant factor at this point, so encoding the claims as bytes beforehand can be a 1.5-2x speedup. If 

