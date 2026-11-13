# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY server/internal/webui/routes.json /server/internal/webui/routes.json
COPY web/ ./
RUN npm run build && test -s dist/index.html

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS backend
WORKDIR /src
COPY server/go.mod server/go.sum ./server/
COPY sdk/go/go.mod ./sdk/go/go.mod
WORKDIR /src/server
RUN go mod download
WORKDIR /src
COPY server/ ./server/
COPY sdk/go/ ./sdk/go/
COPY --from=frontend /web/dist/ ./server/internal/webui/dist/
# Fail closed: never ship a binary containing only the source-tree placeholder.
RUN test -s /src/server/internal/webui/dist/index.html
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=1.0.0
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
WORKDIR /src/server
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X authgo/internal/buildinfo.Version=${VERSION} -X authgo/internal/buildinfo.Commit=${COMMIT} -X authgo/internal/buildinfo.BuiltAt=${BUILD_TIME}" -o /out/authgo ./cmd/authgo \
    && mkdir -p /out/data && chown 65532:65532 /out/data && chmod 0700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="Auth Go" \
      org.opencontainers.image.description="单实例 SQLite 软件授权服务" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=backend /out/authgo /authgo
# An empty named volume inherits this directory's nonroot ownership.
COPY --from=backend --chown=65532:65532 /out/data /data
USER 65532:65532
ENV AUTHGO_ADDR=:8080 AUTHGO_DATA_DIR=/data
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/authgo", "healthcheck"]
ENTRYPOINT ["/authgo"]
