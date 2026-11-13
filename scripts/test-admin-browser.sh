#!/bin/sh
# Fresh real server + production UI regression, invoked by smoke-docker.sh.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${AUTHGO_BROWSER_IMAGE:?requires a locally built application image}"
PREFIX="${AUTHGO_BROWSER_PREFIX:-authgo-admin-browser}-$$"
TMP=$(mktemp -d "$ROOT/.authgo-smoke.browser.XXXXXX")
cleanup() {
  docker rm -f "$PREFIX-browser" "$PREFIX-app" >/dev/null 2>&1 || true
  docker volume rm "$PREFIX-data" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
docker run -d --name "$PREFIX-app" --memory=512m --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --security-opt no-new-privileges:true --cap-drop ALL -p 127.0.0.1::8080 -e AUTHGO_SWAGGER_ENABLED=true -e AUTHGO_TRUSTED_PROXIES= -v "$PREFIX-data:/data" "$AUTHGO_BROWSER_IMAGE" >/dev/null
n=0
until docker exec "$PREFIX-app" /authgo healthcheck >/dev/null 2>&1; do
  n=$((n+1)); [ "$n" -lt 30 ] || { echo 'FAIL browser fixture health'; exit 1; }; sleep 1
done
# Transfer the capability to a private file, never stdout or a process argument.
docker logs "$PREFIX-app" 2>&1 | python3 -c '
import json,sys,pathlib,secrets
rows=[json.loads(line) for line in sys.stdin if line.startswith("{")]
token=next(row["setup_token"] for row in rows if "setup_token" in row)
p=pathlib.Path(sys.argv[1]);p.write_text(json.dumps({"username":"browser-owner","password":secrets.token_hex(24),"token":token}));p.chmod(0o600)
' "$TMP/fixture.json"
ENDPOINT=$(docker port "$PREFIX-app" 8080/tcp)
BEFORE_PID=$(docker inspect --format '{{.State.Pid}}' "$PREFIX-app")
BEFORE_STARTED=$(docker inspect --format '{{.State.StartedAt}}' "$PREFIX-app")
docker run --rm --name "$PREFIX-browser" --memory=1g --shm-size=256m --network host -v "$ROOT:/src:ro" -v "$TMP:/fixture" mcr.microsoft.com/playwright:v1.56.1-noble sh -ec '
  mkdir -p /tmp/tool
  npm install --ignore-scripts --prefix /tmp/tool --no-audit --no-fund playwright@1.56.1 > /tmp/tool/install.log 2>&1 || { cat /tmp/tool/install.log; exit 1; }
  cp /src/web/scripts/test-admin-login-real.mjs /tmp/tool/test.mjs
  cp /src/web/scripts/test-ui-feedback-real.mjs /tmp/tool/test-ui-feedback-real.mjs
  node /tmp/tool/test.mjs "$1" /fixture/fixture.json
' sh "http://$ENDPOINT" &
BROWSER_JOB=$!
RESET_HANDLED=0
while kill -0 "$BROWSER_JOB" 2>/dev/null; do
  if [ "$RESET_HANDLED" = 0 ] && [ -f "$TMP/reset-request" ]; then
    CURRENT=$(docker exec "$PREFIX-app" /authgo admin-path)
    [ "$CURRENT" = /my-console ] || { echo 'FAIL CLI did not show current address'; exit 1; }
    RESET=$(docker exec "$PREFIX-app" /authgo admin-path reset)
    [ "$RESET" = /admin ] || { echo 'FAIL CLI did not reset address'; exit 1; }
    [ "$(docker inspect --format '{{.State.Pid}}' "$PREFIX-app")" = "$BEFORE_PID" ]
    [ "$(docker inspect --format '{{.State.StartedAt}}' "$PREFIX-app")" = "$BEFORE_STARTED" ]
    printf '%s\n' '{"path":"/admin","same_process":true}' > "$TMP/reset-done.tmp"
    mv "$TMP/reset-done.tmp" "$TMP/reset-done.json"
    RESET_HANDLED=1
    echo 'PASS container CLI show/reset changed the live address without restart'
  fi
  sleep 0.1
done
wait "$BROWSER_JOB"
[ "$RESET_HANDLED" = 1 ]
