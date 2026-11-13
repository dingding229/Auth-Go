# syntax=docker/dockerfile:1
# Build on the host architecture, emit the requested target architecture.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY sdk/go/ ./sdk/go/
COPY pack/ ./pack/
RUN cd sdk/go && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /src/pack/stubs/authgo-stub-linux-amd64 ./cmd/authgo-stub \
    && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o /src/pack/stubs/authgo-stub-linux-arm64 ./cmd/authgo-stub
ARG TARGETOS
ARG TARGETARCH
RUN test "$TARGETOS" = linux && case "$TARGETARCH" in amd64|arm64) ;; *) exit 1;; esac \
    && cd pack && CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/authgo-pack ./cmd/authgo-pack
FROM scratch
COPY --from=build /out/authgo-pack /authgo-pack
USER 65532:65532
ENTRYPOINT ["/authgo-pack"]
