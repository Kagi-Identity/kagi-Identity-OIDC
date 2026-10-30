# syntax=docker/dockerfile:1

FROM rust:1.88-bookworm AS builder
WORKDIR /src

# Copy manifests first so dependency compilation can be cached.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY api ./api
COPY static ./static
COPY supabase ./supabase
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /nonexistent kagi \
    && mkdir -p /data \
    && chown -R kagi:kagi /data

WORKDIR /app
COPY --from=builder /src/target/release/kagi /usr/local/bin/kagi
USER 10001:10001

ENV KAGI_BIND=0.0.0.0:8080 \
    KAGI_DB=/data/kagi.db

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kagi"]
