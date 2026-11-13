# syntax=docker/dockerfile:1
ARG AUTHGO_TOOLS_IMAGE=authgo-tools:1.0.0
FROM ${AUTHGO_TOOLS_IMAGE} AS tools
FROM python:3.12-slim AS build
COPY --from=tools /authgo-pack /usr/local/bin/authgo-pack
WORKDIR /src
COPY sdk/python/ ./sdk/python/
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir ./sdk/python
COPY examples/docker-protected/python/ /src/example/
ARG PAYLOAD_PUBLIC_KEY
ARG PAYLOAD_KEY_ID
ARG PAYLOAD_APP_KEY
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN test -n "$AUTHGO_CONFIG" && python /src/example/build.py \
    && authgo-pack --python core=/staging/core --public-key "$PAYLOAD_PUBLIC_KEY" --key-id "$PAYLOAD_KEY_ID" --app-key "$PAYLOAD_APP_KEY" --config "$AUTHGO_CONFIG" --version "$VERSION" --out /payload \
    && mkdir -p /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /opt/venv /opt/venv
COPY --from=build /main.pyc /app/main.pyc
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/opt/venv/bin/python", "/app/main.pyc"]
COPY --from=build --chown=65532:65532 /payload /opt/authgo
