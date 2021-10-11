FROM rust:slim-bullseye AS chef
RUN cargo install cargo-chef
WORKDIR tiauth

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS tiauthbuilder
COPY --from=planner /tiauth/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release

# We do not need the Rust toolchain to run the binary!
FROM debian:buster-slim AS runtime
WORKDIR tiauth
COPY --from=tiauthbuilder /tiauth/target/release/tiauth /usr/local/bin
ENTRYPOINT ["/usr/local/bin/tiauth"]