FROM python:3.12-slim AS build
WORKDIR /src
COPY sdk/python/ ./sdk/python/
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir ./sdk/python
COPY examples/docker/python/main.py /app/main.py
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN test -n "$AUTHGO_CONFIG" && python -c 'import os,pathlib;pathlib.Path("/app/_authgo_build.py").write_text("CONFIG = "+repr(os.environ["AUTHGO_CONFIG"])+"\nVERSION = "+repr(os.environ["VERSION"])+"\n")' \
    && mkdir -p /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /opt/venv /opt/venv
COPY --from=build /app /app
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/opt/venv/bin/python", "/app/main.py"]
