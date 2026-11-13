# syntax=docker/dockerfile:1
ARG AUTHGO_TOOLS_IMAGE=authgo-tools:1.0.0
FROM ${AUTHGO_TOOLS_IMAGE} AS tools
FROM rust:1.96.1-bookworm AS build
COPY --from=tools /authgo-pack /usr/local/bin/authgo-pack
WORKDIR /src
COPY sdk/rust/ ./sdk/rust/
COPY examples/docker-protected/rust/ ./examples/docker-protected/rust/
WORKDIR /src/examples/docker-protected/rust
ARG PAYLOAD_PUBLIC_KEY
ARG PAYLOAD_KEY_ID
ARG PAYLOAD_APP_KEY
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN test -n "$AUTHGO_CONFIG" && dd if=/dev/zero of=padding.bin bs=1048576 count=100 \
    && cargo build --release --locked \
    && cp target/release/authgo-docker-example /app \
    && authgo-pack --protect /app --public-key "$PAYLOAD_PUBLIC_KEY" --key-id "$PAYLOAD_KEY_ID" --app-key "$PAYLOAD_APP_KEY" --config "$AUTHGO_CONFIG" --version "$VERSION" --out /payload \
    && chmod 0555 /app && mkdir -p /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app"]
COPY --from=build /app /app
