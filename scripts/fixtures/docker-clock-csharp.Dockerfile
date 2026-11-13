FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY sdk/csharp/AuthGo/ ./sdk/csharp/AuthGo/
COPY examples/docker/csharp/ ./examples/docker/csharp/
COPY scripts/fixtures/docker-clock-csharp.cs ./examples/docker/csharp/Program.cs
ARG AUTHGO_CONFIG
ARG VERSION=dev
RUN test -n "$AUTHGO_CONFIG" && printf 'internal static class Build { public const string Config = "%s"; public const string Version = "%s"; }\n' "$AUTHGO_CONFIG" "$VERSION" > examples/docker/csharp/Build.cs \
    && dotnet publish examples/docker/csharp/Example.csproj -c Release -o /out --nologo \
    && mkdir /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM mcr.microsoft.com/dotnet/sdk:8.0
ENV DOTNET_EnableDiagnostics=0 DOTNET_CLI_TELEMETRY_OPTOUT=1
COPY --from=build /out /app
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["dotnet", "/app/Example.dll"]
