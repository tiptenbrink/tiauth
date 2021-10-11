# tiauth
Rust authentication server using warp

json-file based

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