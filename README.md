# tiauth
Rust authentication server using warp

json-file based -> migrating to diesel sqlite

### Deployment

In the following examples, replace `tmtenbrink` with your own Docker Hub repo.

Build using:

```shell
docker build --tag tmtenbrink/tiauth .
```

Push it to Docker Hub using:

```shell
docker push tmtenbrink/tiauth
```

It can then be deployed on any server with Docker and Docker Compose (V2) by distributing the files in `/deployment` to the servers and running `deployment/deploy.sh`. This deployment can be configured by modifying the `.env` file.

## Authentication schema

### Register

(Resource client)

A 16-byte salt is generated (crypto random values), hexed

A password hash is generated (PBKDF2, 100000 iterations SHA-256), 256 bits, hexed

This is posted to the auth server

(Auth server)

Public and private ed25519 key is generated (OsRng) and saved along with user_hex, password_hash_hex and salt_hex

Empty claims entry is also created

### Login

(Resource client)

Salt is requested from server
(Auth server sends directly from database)

Password hash is recreated

Sent along with username to auth server

(Auth server)

Password hash comparison

JWT construction: 
- standard header (indicating ed25519 and jwt), base64_url encoded
- claims read from file
- payload is created:
  - indicates issuer
  - indicates unix issuing time
  - indicates subject (user hex)
  - contains tiauth claims (per resource the permission and uuid and uri)
- payload b64urlencoded
- appended with '.' to header
- now combined is signed (with private key) and this is b64urlencoded and added to the earlier combined = JWT

(Resource client)

JWT is received and posted to the login flow of the resource server

(Resource server)

Public key is requested from server
(Auth server sends directly from database)

JWT signature is verified using public key on resource server

If correct, jwt cookie is created

### Requesting resource

(Resource server)

Responds to client request. First verifies JWT (with public key from auth server)

Looks at resource claims in the JWT

Does lookup for resources, checks if UUID are equal. If so, supplies it

## DB tests
"user_hex": "61-61-70",
"password_hash_hex": "4c2490ff0f247e20b7ac5925829eb99e0d201ae43ee12c67d58248a291f32bdd",
"salt_hex": "74c9e15a6b5c71b10cadbbd594f0f5b1",
"secret_hex": "3551858c6566cd33211ee8dba3dce97d26e24f26ce641bb658b5f8223e5c567d",
"public_hex": "f9b8a37df8f3b22b0db9e9cb9e53ba6681bce728b9b9de84ae50482efbef181c"

```sqlite
INSERT INTO user_auth (user_hex, password_hash_hex, salt_hex, secret_hex, public_hex)
VALUES('61-61-70', '4c2490ff0f247e20b7ac5925829eb99e0d201ae43ee12c67d58248a291f32bdd', '74c9e15a6b5c71b10cadbbd594f0f5b1', '3551858c6566cd33211ee8dba3dce97d26e24f26ce641bb658b5f8223e5c567d', 'f9b8a37df8f3b22b0db9e9cb9e53ba6681bce728b9b9de84ae50482efbef181c')
```