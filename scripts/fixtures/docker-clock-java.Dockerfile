FROM eclipse-temurin:17-jdk AS build
WORKDIR /src
COPY sdk/java/src/main/java/ ./sdk/
COPY scripts/fixtures/docker-clock-java.java ./ClockAgent.java
COPY scripts/fixtures/docker-reclaim-java.java ./ReclaimProbe.java
ARG AUTHGO_CONFIG
RUN test -n "$AUTHGO_CONFIG" && mkdir /out && javac -d /out sdk/io/authgo/*.java ClockAgent.java ReclaimProbe.java \
    && printf 'config=%s\n' "$AUTHGO_CONFIG" > /out/authgo-build.properties \
    && jar --create --file /app.jar --main-class io.authgo.ClockAgent -C /out . \
    && mkdir /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM eclipse-temurin:17-jdk
COPY --from=build /app.jar /app.jar
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=65", "-jar", "/app.jar"]
