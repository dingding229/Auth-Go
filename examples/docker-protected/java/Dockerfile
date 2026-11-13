# syntax=docker/dockerfile:1
ARG AUTHGO_TOOLS_IMAGE=authgo-tools:1.0.0
FROM ${AUTHGO_TOOLS_IMAGE} AS tools
FROM eclipse-temurin:17-jdk AS build
COPY --from=tools /authgo-pack /usr/local/bin/authgo-pack
COPY sdk/java/src/main/java/ /src/sdk/
COPY examples/docker-protected/java/ /src/example/
ARG PAYLOAD_PUBLIC_KEY
ARG PAYLOAD_KEY_ID
ARG PAYLOAD_APP_KEY
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN sh /src/example/build.sh \
    && authgo-pack --java app=/business.jar --public-key "$PAYLOAD_PUBLIC_KEY" --key-id "$PAYLOAD_KEY_ID" --app-key "$PAYLOAD_APP_KEY" --config "$AUTHGO_CONFIG" --version "$VERSION" --out /payload \
    && mkdir -p /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM eclipse-temurin:17-jre
COPY --from=build /launcher.jar /app/launcher.jar
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=65", "-jar", "/app/launcher.jar"]
COPY --from=build --chown=65532:65532 /payload /opt/authgo
