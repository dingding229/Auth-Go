FROM rust:1.96.1-bookworm AS build
WORKDIR /src
COPY sdk/rust/ ./sdk/rust/
COPY examples/docker/rust/ ./examples/docker/rust/
WORKDIR /src/examples/docker/rust
ARG AUTHGO_CONFIG
RUN test -n "$AUTHGO_CONFIG" && cargo build --release --locked \
    && mkdir -p /out/cache && chown 65532:65532 /out/cache && chmod 0700 /out/cache
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/examples/docker/rust/target/release/authgo-docker-example /app
COPY --from=build --chown=65532:65532 /out/cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app"]
