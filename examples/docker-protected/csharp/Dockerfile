# syntax=docker/dockerfile:1
ARG AUTHGO_TOOLS_IMAGE=authgo-tools:1.0.0
FROM ${AUTHGO_TOOLS_IMAGE} AS tools
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
COPY --from=tools /authgo-pack /usr/local/bin/authgo-pack
WORKDIR /src
COPY sdk/csharp/AuthGo/ ./sdk/csharp/AuthGo/
COPY examples/docker-protected/csharp/ ./examples/docker-protected/csharp/
ARG PAYLOAD_PUBLIC_KEY
ARG PAYLOAD_KEY_ID
ARG PAYLOAD_APP_KEY
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN sh examples/docker-protected/csharp/build.sh \
    && authgo-pack --dotnet app=/business/Core.dll --public-key "$PAYLOAD_PUBLIC_KEY" --key-id "$PAYLOAD_KEY_ID" --app-key "$PAYLOAD_APP_KEY" --config "$AUTHGO_CONFIG" --version "$VERSION" --out /payload \
    && mkdir -p /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM mcr.microsoft.com/dotnet/runtime:8.0
ENV DOTNET_EnableDiagnostics=0 DOTNET_CLI_TELEMETRY_OPTOUT=1
COPY --from=build /public /app
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["dotnet", "/app/Launcher.dll"]
COPY --from=build --chown=65532:65532 /payload /opt/authgo
