FROM php:8.1-fpm AS build
COPY sdk/php/src/ /app/sdk/
COPY scripts/fixtures/docker-clock-php-fpm.php /app/index.php
COPY examples/docker/php-fpm/php-fpm.conf /app/php-fpm.conf
ARG AUTHGO_CONFIG
ARG VERSION=dev
RUN test -n "$AUTHGO_CONFIG" && php -r 'file_put_contents("/app/authgo-build.php","<?php const CONFIG=".var_export(getenv("AUTHGO_CONFIG"),true)."; const VERSION=".var_export(getenv("VERSION"),true).";\n");' \
    && mkdir /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM php:8.1-fpm
COPY --from=build /app /app
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 9000
ENTRYPOINT ["php-fpm", "--nodaemonize", "--fpm-config", "/app/php-fpm.conf"]
