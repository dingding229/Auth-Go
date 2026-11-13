FROM golang:1.26-alpine AS build
WORKDIR /src/sdk/go
COPY sdk/go/ ./
COPY scripts/fixtures/docker-clock_test.go ./docker_clock_test.go
ARG AUTHGO_CONFIG
RUN CGO_ENABLED=0 go test -c -trimpath -ldflags "-s -w -X authgo/sdk.dockerClockConfig=$AUTHGO_CONFIG" -o /out/clock . \
    && mkdir -p /out/cache && chown 65532:65532 /out/cache && chmod 0700 /out/cache
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/clock /clock
COPY --from=build --chown=65532:65532 /out/cache /var/lib/authgo
USER 65532:65532
ENTRYPOINT ["/clock", "-test.run=^TestDockerClockAgent$"]
