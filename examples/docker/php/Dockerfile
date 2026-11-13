FROM php:8.1-cli AS build
RUN docker-php-ext-install pcntl >/dev/null
COPY sdk/php/src/ /app/sdk/
COPY examples/docker/php/main.php /app/main.php
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN test -n "$AUTHGO_CONFIG" && php -r 'file_put_contents("/app/authgo-build.php","<?php const CONFIG=".var_export(getenv("AUTHGO_CONFIG"),true)."; const VERSION=".var_export(getenv("VERSION"),true).";\n");' \
    && mkdir /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM php:8.1-cli
COPY --from=build /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/
COPY --from=build /usr/local/etc/php/conf.d/ /usr/local/etc/php/conf.d/
COPY --from=build /app /app
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["php", "/app/main.php"]
