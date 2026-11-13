FROM php:8.1-apache AS build
COPY sdk/php/src/ /app/sdk/
COPY examples/docker/php-apache/index.php /app/public/index.php
COPY examples/docker/php-apache/apache.conf /app/apache.conf
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN test -n "$AUTHGO_CONFIG" && php -r 'file_put_contents("/app/authgo-build.php","<?php const CONFIG=".var_export(getenv("AUTHGO_CONFIG"),true)."; const VERSION=".var_export(getenv("VERSION"),true).";\n");' \
    && mkdir /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM php:8.1-apache
COPY --from=build /app /app
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGWINCH
ENTRYPOINT ["apache2", "-f", "/app/apache.conf", "-DFOREGROUND"]
