# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY sdk/go/ ./sdk/go/
COPY examples/docker/ ./examples/docker/
WORKDIR /src/examples/docker
ARG VERSION=1.0.0
ARG AUTHGO_CONFIG
RUN test -n "$AUTHGO_CONFIG" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION -X main.authConfig=$AUTHGO_CONFIG" -o /out/app . \
    && mkdir -p /out/cache && chown 65532:65532 /out/cache && chmod 0700 /out/cache

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
COPY --from=build --chown=65532:65532 /out/cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app"]
