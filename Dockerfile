FROM rust:slim AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates crates

RUN cargo build --release --bin aws-iam-grapher

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/aws-iam-grapher /usr/local/bin/aws-iam-grapher

ENTRYPOINT ["/usr/local/bin/aws-iam-grapher"]
