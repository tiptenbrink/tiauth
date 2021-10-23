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