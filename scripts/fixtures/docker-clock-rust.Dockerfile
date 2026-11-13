FROM rust:1.96.1-bookworm AS build
WORKDIR /src/sdk/rust
COPY sdk/rust/ ./
COPY scripts/fixtures/docker-clock-rust.rs ./examples/docker_clock.rs
ARG AUTHGO_CONFIG
RUN test -n "$AUTHGO_CONFIG" && cargo build --locked --release --example docker_clock \
    && mkdir -p /out/cache && chown 65532:65532 /out/cache && chmod 0700 /out/cache
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/sdk/rust/target/release/examples/docker_clock /clock
COPY --from=build --chown=65532:65532 /out/cache /var/lib/authgo
USER 65532:65532
ENTRYPOINT ["/clock"]
