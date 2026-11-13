#!/bin/sh
set -eu
# These are compile-time string literals, never a runtime config resource.
case "$AUTHGO_CONFIG" in authgo2.*) ;; *) exit 1;; esac
case "$AUTHGO_CONFIG$VERSION" in *[!A-Za-z0-9._+-]*) exit 1;; esac
mkdir -p /out/launcher /out/business
printf 'import io.authgo.*; public final class Launcher { public static void main(String[] args) { var options = new GuardOptions(); options.config = "%s"; options.version = "%s"; try { Bootstrap.run(options, "app", args); } catch (Throwable error) { if (error instanceof Client.AuthGoException problem) System.err.println(problem.code); else System.err.println("Protected startup failed"); System.exit(Guard.EXIT_LICENSE); } } }\n' "$AUTHGO_CONFIG" "$VERSION" > /src/Launcher.java
javac -d /out/launcher /src/sdk/io/authgo/*.java /src/Launcher.java
javac -cp /out/launcher -d /out/business /src/example/Main.java
jar --create --file /launcher.jar --main-class Launcher -C /out/launcher .
jar --create --file /business.jar --main-class Main -C /out/business .
