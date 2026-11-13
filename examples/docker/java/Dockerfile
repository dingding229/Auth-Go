FROM eclipse-temurin:17-jdk AS build
WORKDIR /src
COPY sdk/java/src/main/java/ ./sdk/
COPY examples/docker/java/Main.java ./Main.java
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN test -n "$AUTHGO_CONFIG" && mkdir /out && javac -d /out sdk/io/authgo/*.java Main.java \
    && printf 'config=%s\nversion=%s\n' "$AUTHGO_CONFIG" "$VERSION" > /out/authgo-build.properties \
    && jar --create --file /app.jar --main-class Main -C /out . \
    && mkdir /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM eclipse-temurin:17-jdk
COPY --from=build /app.jar /app.jar
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=65", "-jar", "/app.jar"]
