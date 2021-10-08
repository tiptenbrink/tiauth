# tiauth
Rust authentication server using warp

json-file based -> migrating to diesel sqlite

### Deployment

```shell
docker build --tag tmtenbrink/tiauth .
```

You can then run it in the background using:

```shell
docker run -d -p 127.0.0.1:3031:3031 tmtenbrink/tiauth
```