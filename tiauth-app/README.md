## Performance

Other notes:
up to 1 kB: sign 0.25 ms
1 - 100 kB: sign up to 1 ms.

Load key from PEM: 0.6-0.8 ms. Faster when OpenSSL has already been called.
Load key from raw bytes: 0.2 ms.

TODO look at performance of ed25519 and then ed25519 dalek