# syntax=docker/dockerfile:1
ARG AUTHGO_TOOLS_IMAGE=authgo-tools:1.0.0
FROM ${AUTHGO_TOOLS_IMAGE} AS tools
FROM node:22-alpine AS build
COPY --from=tools /authgo-pack /usr/local/bin/authgo-pack
COPY sdk/node/*.js sdk/node/package.json /launcher-sdk/
COPY examples/docker-protected/node/ /src/example/
ARG PAYLOAD_PUBLIC_KEY
ARG PAYLOAD_KEY_ID
ARG PAYLOAD_APP_KEY
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN test -n "$AUTHGO_CONFIG" && node /src/example/build.mjs \
    && authgo-pack --node core=/src/example/core.cjs --public-key "$PAYLOAD_PUBLIC_KEY" --key-id "$PAYLOAD_KEY_ID" --app-key "$PAYLOAD_APP_KEY" --config "$AUTHGO_CONFIG" --version "$VERSION" --out /payload \
    && mkdir -p /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM node:22-alpine
WORKDIR /app
COPY --from=build /launcher-sdk/ /app/sdk/
COPY --from=build /launcher/main.mjs /app/main.mjs
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["node", "/app/main.mjs"]
COPY --from=build --chown=65532:65532 /payload /opt/authgo
