heed
https://github.com/meilisearch/heed

sqlite
- boringdb? https://medium.com/themelio/boringdb-a-high-performance-key-value-store-built-on-sqlite-b4bb72beaf76
- do it yourself https://github.com/the-lean-crate/criner/issues/1
https://rodydavis.com/sqlite/key-value
https://github.com/rusqlite/rusqlite

redb
https://github.com/cberner/redb

# For who?

`tiauth` is made to manage user accounts for applications you control. Don't use it for external, untrusted applications. If you are at that level of complexity, just use OAuth and friends.

Do you:
- Have a few hundred to a few thousand (or maybe ten housands) users?
- Run a few services fully controlled by you?
- Want a single authentication solution for all of them?

Then `tiauth` is for you.

Or maybe you just run your own little homelab and want a unified authentication solution? `tiauth` is for hobbyists, small companies and organizations. To make things simpler, but still provide full control.


# Architecture

`tiauth` is a simple, password-based authentication server. It uses the OPAQUE protocol to ensure a user's password is never seen by the server, while at the same time being resistant to pre-computation attacks (where an attacker requests the user's password salt and computes a rainbow table, which can be utilized upon server compromise). Furthermore, it does not follow the complex OAuth 2.0 standard, which is focused on authorization and is hard to get right. Instead, it issues database-tracked sessions. On user requests, an application checks with `tiauth` if the session is still valid. They can be revoked by the application and user. However, the application can choose to also respect the cryptograhpic signature of the session token given to the client, only checking its status with `tiauth` ocasionally. An application can store arbitrary binary data (up to 128 kB) representing information about the user, the "claims".

# Setup

`tiauth` allows you to scope users to specific namespaces, called "applications". Before you can do this, you need to register such an application. There's two ways to do this: 
1. (easy) hardcode these applications into the code that consumes this library
2. (harder) 

# Operations

`create_user(app, user_id)`:
    <!-- - Proof level: `application` or `none` -->
    - Prerequisites: `app` has been registered, 

`reset_password(app, user_id)`:

``

<!-- Some operations require "proof". There are two types of proof: -->

# Claims structure

The `claims` is a [MessagePack](https://msgpack.org/) map, where each key is a string (so it's UTF-8). The values can be any valid MsgPack, but if they are nested structures, note that the default recursion limit is 1024. Also, the claims must fit within 128 kB. It is up to the application to ensure there are no duplicate keys and that each key is indeed a string.

# Security model

## Registration

By default, any user can register for your application.

When someone calls `start_register` (providing the application and their preferred user_id), the server computes the OPAQUE response and hands out a NewUser nonce. 
It will do this even if someone has already registered using that user_id.

When someone calls `register_finish` with a NewUser nonce, no status is returned. 

<!-- ### Proof-mode -->

### Enumeration

The application 

#### Login

Client provides request + nonce. Server writes at nonce key. While client can choose whatever nonce (of specific length)


# Example flow

1. App: reset password
2. Go to e-mail



For encryption signing... check if msgpack deterministic?


TODO, revoke sessions when modified



#### Model

As the client, we want have:

"claims", which are just maps, with string keys dict[str, Any]
{
    key: value
}

but claims are also blobs, because they can be quite big. The values can also be quite big.

We don't really want to expose the structure of proof use to applications.

# App API

Every request or call is a simple map type, with primitive or simple sequence values. 

## App library

`create_proof`:


## HTTP

`register/start`:
```
model json {
    application: str
    opaque_request: str  # output from opaque_register_client
    user_id: st
} -> json {
    start_nonce: str
    opaque_response: str
}
```

`register/finish`:
```
model json {
    application: str
    opaque_request: str  # output from opaque_register_client_finish
    start_nonce: str  # output from register_start
    claims_proof?: str | null  # output from create_set_claims_proof
} -> ok
```

`login/start`:
```
model json {
    application: str
    opaque_request: str  # output from opaque_login_client
    user_id: st
} -> json {
    start_nonce: str
    opaque_response: str
}
```

`login/session`:
```
model json {
    application: str
    opaque_request: str  # output from opaque_login_client_finish
    start_nonce: str  # output from login_start
    pake_secret: str  # output from opaque_login_client_finish
        all_claims: true ;
        requested_claims: list[str]
} -> ok
```

### Issues with rust-analyzer target dir contention and PyO3 recompiling

For the PyO3 problem, create a directory inside the repository called `.cargo` and create the following a file called `config.toml`:
```toml
[env]
PYO3_PYTHON = "<path to virtual environment python interpreter of tiauth-app-py>"
```

For the target dir contention, add the following to your VS Code JSON settings:

```json
"rust-analyzer.server.extraEnv": {
    "CARGO_TARGET_DIR": "target/analyzer"
},
"rust-analyzer.check.extraArgs": [
    "--target-dir=target/analyzer"
],
```

Note that this can lead to significantly more storage requirements.

### Why no rkyv

redb cannot store bytes in an aligned way. This is required for rkyv's zero-copy deserialization. 

### Use unix domain sockets in Docker

https://blog.myhro.info/2017/01/benchmarking-ip-and-unix-domain-sockets-for-real


### Key rotation

We want 

### Mutability

We need some way to add applications at runtime. But this requires modifying the state. This means AppTables etc. has to all be wrapped in Mutex.

- Adding an 

### Login performance

The login server time is about 2.1 ms, of which 1.2 ms is the login_start. This is with no claims.

### Database performance

Opening, writing and comitting a write transaction takes ~1 ms. A 1 MB write can be completed in around ~10 ms.

Opening and reading a read transaction takes less than 1 us.

When applying significant load through concurrent requests, we can serve about 4000 requests in ~10 seconds (400 ops/sec). 2000 of these are requests that require a write to the database, and these take up the vast majority of time.

Writing a user, which is not small because the password file can be quite long, can take up to 4 ms. Writing a small set of claims can take 2 ms. Some tests consisting of 10000 claims for a single user can take up to 20 ms.

Throughout this, all 16 logical cores reached a constant utilization of around 15-20% (meaning a total scaling factor of 2-3).

Another scenario, which consisted of only requesting proof tokens, served 10000 requests in ~4.5 seconds (2200 ops/sec). The other opposite is only registering users, where 1000 could be served in ~8 seconds (125 ops/sec).

Assuming an average write will cost around 5 ms, realistically, better storage, memory and processors will not push this much lower than 1 ms. Therefore, on an enterprise-grade system, a single application can be expected to handle around, AT MOST, 1000 writes per second. Assuming something like 20% registrations vs current users, and each user requiring claims updates at least once a day, let's assume 61 ms of time per user per month. This means that a tiauth application could scale to 40 million users per month. Although, depending on the workload (in some cases most users could be expected to rapidly change claims, which could would make something like 20 SECONDS of time per user per month not that crazy), this could be as low as 100,000 users per month.

After looking at some more stats... the total CPU utilization of tiauth does not even reach 1%. Disk utilization does not reach more than 3 MB/s (it reports max 20% utilization).
Some huge IO bottlenecks must remain.

### Ephemeral:

NewUser,
ChangePassword,
SetPassword,
Opaque,



TODO DRIVE time only from state, no calls in application code to SystemTime


For ephemeral login we need:
- durable version counter that is incremented on each login


Ephemeral:

When logging, two rounds of computation are necessary due to the use of the OPAQUE protocol:

- `login_start` computes an OPAQUE message for the user as well as some state that must be used in the second step. We want to avoid any database writes,
so we HMAC this state (together with the user_id and some other information), creating an Ephemeral. This is passed to the user.
- `login_finish` takes the user OPAQUE message and the Ephemeral from the previous step. It verifies the ephemeral and uses the state stored in it to finish the OPAQUE protocol.

This protocol has a problem. The Ephemeral from the first time can be reused as often as a user wishes, as we store no state. This can be partially alleviated by setting an expiry time, after which the server will deny it being used again, but we wish to deny it being used even twice, to ensure the OPAQUE protocol is always executed in the way it was intended. So some kind of state must be remembered. Specifically, an Ephemeral has some kind of id/count associated with it. This id must be checked to see if it has been used.

Furthermore, the key used to sign the HMAC is known only to the server, so it must be stored somewhere. 


### Subset algo results

```
k=3, n=30
elapsed conv: 0.028073 ms
linear: 27 ops.
took 0.001052 ms.
binary est: 9.813781 ops.
took 0.009508001 ms.
binary split par: 11.813781 ops.
took 0.64613295 ms.
binary split: 11.813781 ops.
took 0.001112 ms.
binary split par extend: 11.813781 ops.
took 0.053662 ms.
---
k=87, n=200
elapsed conv: 0.078539 ms
linear: 200 ops.
took 0.014266999 ms.
binary est: 554.38715 ops.
took 0.026089 ms.
binary split par: 238.25047 ops.
took 0.692902 ms.
binary split: 238.25046 ops.
took 0.020919 ms.
binary split par extend: 238.25047 ops.
took 0.055905998 ms.
---
k=90, n=2000
elapsed conv: 0.463888 ms
linear: 1997 ops.
took 0.029817 ms.
binary est: 876.86035 ops.
took 0.031059 ms.
binary split par: 554.9355 ops.
took 0.7075 ms.
binary split: 554.9355 ops.
took 0.023815 ms.
binary split par extend: 554.9355 ops.
took 0.117593 ms.
---
k=1420, n=2000
elapsed conv: 0.55556196 ms
linear: 2000 ops.
took 0.242469 ms.
binary est: 13537.123 ops.
took 0.347388 ms.
binary split par: 2897.8623 ops.
took 1.230409 ms.
binary split: 2897.8657 ops.
took 0.238672 ms.
binary split par extend: 2897.8623 ops.
took 0.186042 ms.
---
k=1982, n=2000
elapsed conv: 0.563808 ms
linear: 2000 ops.
took 0.34431198 ms.
binary est: 18878.848 ops.
took 0.473166 ms.
binary split par: 2749.3606 ops.
took 1.139899 ms.
binary split: 2749.3633 ops.
took 0.246897 ms.
binary split par extend: 2749.3606 ops.
took 0.212713 ms.
---
k=197916, n=200000
elapsed conv: 69.85484 ms
linear: 200000 ops.
took 28.181545 ms.
binary est: 3199808.8 ops.
took 55.45554 ms.
binary split par: 294194.8 ops.
took 40.80323 ms.
binary split: 294202.28 ops.
took 30.206268 ms.
binary split par extend: 294194.8 ops.
took 25.410408 ms.
---
k=1979915, n=2000000
elapsed conv: 947.8669 ms
linear: 2000000 ops.
took 267.114 ms.
binary est: 38443096 ops.
took 601.4376 ms.
binary split par: 2779608.5 ops.
took 409.5743 ms.
binary split: 2767521.3 ops.
took 321.19016 ms.
binary split par extend: 2779608.5 ops.
took 320.85025 ms.
---
k=99874, n=2000000
elapsed conv: 678.6542 ms
linear: 1999979 ops.
took 20.629108 ms.
binary est: 1946838.3 ops.
took 60.031284 ms.
binary split par: 610941.8 ops.
took 34.32081 ms.
binary split: 610947.4 ops.
took 46.59607 ms.
binary split par extend: 610941.8 ops.
took 14.933323 ms.
---
k=9819, n=2000000
elapsed conv: 669.37445 ms
linear: 1999711 ops.
took 9.914402 ms.
binary est: 191234.33 ops.
took 21.430904 ms.
binary split par: 92930.65 ops.
took 4.178592 ms.
binary split: 92930.98 ops.
took 5.8565392 ms.
binary split par extend: 92930.65 ops.
took 1.160888 ms.
---
k=1002, n=2000000
elapsed conv: 657.4642 ms
linear: 1996903 ops.
took 6.882079 ms.
binary est: 19557.818 ops.
took 3.288105 ms.
binary split par: 12730.44 ops.
took 1.160878 ms.
binary split: 12730.447 ops.
took 0.804763 ms.
binary split par extend: 12730.44 ops.
took 0.16901 ms.
---
k=113, n=2000000
elapsed conv: 668.1629 ms
linear: 1998014 ops.
took 6.672843 ms.
binary est: 2193.7527 ops.
took 0.231318 ms.
binary split par: 1794.3739 ops.
took 0.756051 ms.
binary split: 1794.374 ops.
took 0.090151 ms.
binary split par extend: 1794.3739 ops.
took 0.064922996 ms.
---
k=13, n=2000000
elapsed conv: 803.1828 ms
linear: 1830818 ops.
took 12.435755 ms.
binary est: 262.94495 ops.
took 0.071504995 ms.
binary split par: 244.64317 ops.
took 0.88305104 ms.
binary split: 244.64319 ops.
took 0.01608 ms.
binary split par extend: 244.64317 ops.
took 0.034764998 ms.
--- (big values)
k=213, n=20000
elapsed conv: 336.96924 ms
linear: 19862 ops.
took 3.0210168 ms.
binary est: 2739.6924 ops.
took 2.296786 ms.
binary split par: 1779.1162 ops.
took 2.5930479 ms.
binary split: 1779.1161 ops.
took 1.87528 ms.
binary split par extend: 1779.1162 ops.
took 0.612589 ms.
---
k=218, n=20000
elapsed conv: 325.30405 ms
linear: 19979 ops.
took 2.972367 ms.
binary est: 2781.5813 ops.
took 2.087973 ms.
binary split par: 1818.6095 ops.
took 2.618117 ms.
binary split: 1818.6089 ops.
took 1.911458 ms.
binary split par extend: 1818.6095 ops.
took 0.55707395 ms.
```

### Mutability

We can open databases only once