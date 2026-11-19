# syntax=docker/dockerfile:1
FROM rust:bookworm AS build
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN groupadd --gid 10001 rustine && useradd --system --uid 10001 --gid rustine --no-create-home rustine \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/rustine /usr/local/bin/rustine
USER rustine
EXPOSE 443/tcp 8443/tcp
ENTRYPOINT ["/usr/local/bin/rustine"]

# Test stage is intentionally separate from the minimal production runtime.
FROM rust:bookworm AS test
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl python3 nodejs openssl tcpdump ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY . .
RUN chmod +x scripts/*.sh \
 && scripts/make-certs.sh relay.test /testcerts/relay \
 && scripts/make-certs.sh exit.test /testcerts/exit \
 && cargo build \
 && cargo test --no-run
RUN cp target/debug/rustine /usr/local/bin/rustine
