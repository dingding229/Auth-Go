FROM node:22-alpine AS build
WORKDIR /src
COPY sdk/node/ ./sdk/node/
COPY examples/docker/node/ ./examples/docker/node/
WORKDIR /src/examples/docker/node
RUN npm install --omit=dev --ignore-scripts --install-links --no-audit --no-fund
ARG AUTHGO_CONFIG
ARG VERSION=1.0.0
RUN test -n "$AUTHGO_CONFIG" && node --input-type=module -e 'import fs from "node:fs";fs.writeFileSync("authgo-build.json",JSON.stringify({config:process.env.AUTHGO_CONFIG,version:process.env.VERSION}))' \
    && mkdir -p /cache && chown 65532:65532 /cache && chmod 0700 /cache
FROM node:22-alpine
WORKDIR /app
COPY --from=build /src/examples/docker/node/main.mjs ./
COPY --from=build /src/examples/docker/node/authgo-build.json ./
COPY --from=build /src/examples/docker/node/node_modules ./node_modules
COPY --from=build --chown=65532:65532 /cache /var/lib/authgo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["node", "/app/main.mjs"]
