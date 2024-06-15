heed
https://github.com/meilisearch/heed

sqlite
- boringdb? https://medium.com/themelio/boringdb-a-high-performance-key-value-store-built-on-sqlite-b4bb72beaf76
- do it yourself https://github.com/the-lean-crate/criner/issues/1
https://rodydavis.com/sqlite/key-value
https://github.com/rusqlite/rusqlite

redb
https://github.com/cberner/redb


### Architecture

`tiauth` is a simple, password-based authentication server. It uses the OPAQUE protocol to ensure a user's password is never seen by the server, while at the same time being resistant to pre-computation attacks (where an attacker requests the user's password salt and computes a rainbow table, which can be utilized upon server compromise). Furthermore, it does not follow the complex OAuth 2.0 standard, which is focused on authorization and is hard to get right. Instead, it issues database-tracked sessions. On user requests, an application checks with `tiauth` if the session is still valid. They can be revoked by the application and user. However, the application can choose to also respect the cryptograhpic signature of the session token given to the client, only checking its status with `tiauth` ocasionally. An application can store arbitrary binary data (up to 128 kB) representing information about the user, the "claims".


### Security model


#### Registration


#### Login

Client provides request + nonce. Server writes at nonce key. While client can choose whatever nonce (of specific length)