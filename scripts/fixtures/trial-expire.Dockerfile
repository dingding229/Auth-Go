FROM golang:1.26-alpine AS build
WORKDIR /src
COPY server/ ./server/
COPY sdk/go/ ./sdk/go/
COPY scripts/fixtures/trial-expire.go ./server/cmd/authgo-trial-expire/main.go
WORKDIR /src/server
RUN CGO_ENABLED=0 go build -trimpath -o /out/expire ./cmd/authgo-trial-expire
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/expire /expire
USER 65532:65532
ENTRYPOINT ["/expire"]
