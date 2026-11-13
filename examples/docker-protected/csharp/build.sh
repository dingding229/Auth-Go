#!/bin/sh
set -eu
case "$AUTHGO_CONFIG" in authgo2.*) ;; *) exit 1;; esac
case "$AUTHGO_CONFIG$VERSION" in *[!A-Za-z0-9._+-]*) exit 1;; esac
printf 'internal static class Build { public const string Config = "%s"; public const string Version = "%s"; }\n' "$AUTHGO_CONFIG" "$VERSION" > /src/examples/docker-protected/csharp/Launcher/Build.cs
dotnet publish /src/examples/docker-protected/csharp/Launcher/Launcher.csproj -c Release -o /public --nologo -p:DebugType=None -p:DebugSymbols=false
dotnet publish /src/examples/docker-protected/csharp/Business/Core.csproj -c Release -o /business --nologo -p:DebugType=None -p:DebugSymbols=false
