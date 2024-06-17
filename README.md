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

By default, any user can register for your application. If they try to register when someone has already registered, it will be a no-op.

<!-- ### Proof-mode -->

### Enumeration

The application 

#### Login

Client provides request + nonce. Server writes at nonce key. While client can choose whatever nonce (of specific length)


# Example flow

1. App: reset password
2. Go to e-mail



For encryption signing... check if msgpack deterministic?