FROM rust:slim-bullseye

ADD . ./opt/tiauth

WORKDIR /opt/tiauth

RUN cargo build --release

ENTRYPOINT ["./entrypoint.sh"]