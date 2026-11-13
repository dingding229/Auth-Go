# syntax=docker/dockerfile:1
ARG AUTHGO_TOOLS_IMAGE=authgo-tools:1.0.0
FROM ${AUTHGO_TOOLS_IMAGE} AS tools
FROM php:8.1-fpm AS build
COPY --from=tools /authgo-pack /usr/local/bin/authgo-pack
RUN docker-php-ext-install opcache >/dev/null
COPY sdk/php/src/ /sdk/
COPY examples/docker-protected/php-fpm/ /src/example/
ARG PAYLOAD_PUBLIC_KEY
ARG PAYLOAD_KEY_ID
ARG PAYLOAD_APP_KEY
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN test -n "$AUTHGO_CONFIG" && mkdir /public && php /src/example/build.php \
    && authgo-pack --php core=/src/example/core --public-key "$PAYLOAD_PUBLIC_KEY" --key-id "$PAYLOAD_KEY_ID" --app-key "$PAYLOAD_APP_KEY" --config "$AUTHGO_CONFIG" --version "$VERSION" --out /payload \
    && mkdir -p /cache && chown 65532:65532 /cache && chmod 0700 /cache
# Pristine runtime never sees business sources, build config or pack output.
# Flatten after removing the public PHP build/test corpus, not business code.
FROM php:8.1-fpm AS runtime
RUN rm -rf /usr/src
FROM scratch
COPY --from=runtime / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PHP_INI_DIR=/usr/local/etc/php
COPY --from=build /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/
COPY --from=build /usr/local/etc/php/conf.d/ /usr/local/etc/php/conf.d/
COPY --from=build /sdk/ /app/sdk/
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
COPY --from=build /public/index.php /app/index.php
COPY --from=build /public/release.php /app/release.php
COPY examples/docker-protected/php-fpm/php-fpm.conf /app/php-fpm.conf
COPY --chmod=0555 examples/docker-protected/php-fpm/entrypoint.sh /app/entrypoint.sh
USER 65532:65532
EXPOSE 9000
STOPSIGNAL SIGTERM
ENTRYPOINT ["/app/entrypoint.sh", "php-fpm", "--nodaemonize", "--fpm-config", "/app/php-fpm.conf"]
COPY --from=build --chown=65532:65532 /payload /opt/authgo
