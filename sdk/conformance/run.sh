#!/bin/sh
# Only Docker + POSIX shell/tar are required on the host. No language toolchain.
set -eu
# Check both host filesystems before touching Docker (Colima stores data on host).
check_disk() {
    available=$(LC_ALL=C df -Pk "$1" | awk 'END { print $4 }')
    case "$available" in ''|*[!0-9]*) printf '错误：无法检查磁盘可用空间：%s\n' "$1" >&2; exit 1;; esac
    if [ "$available" -lt 10485760 ]; then
        printf '错误：%s 所在磁盘可用空间不足 10GB（当前 %s KiB），已停止 SDK 测试，未启动 Docker。\n' "$1" "$available" >&2
        exit 1
    fi
}
check_disk "$PWD"
check_disk "${TMPDIR:-/tmp}"
cd "$(dirname "$0")/../.."
scope=$(basename "$(dirname "$PWD")")
case "$scope" in ''|*[!a-z0-9_-]*|[-_]*) scope=sdk;; esac
prefix="authgo-${scope}-sdk"
session="$prefix-$(date +%s)-$$"
image="$session-tools"
cleanup() {
    ids=$(docker ps -aq --filter "label=authgo.sdk.session=$session" 2>/dev/null || true)
    if [ -n "$ids" ]; then docker rm -f $ids >/dev/null 2>&1 || true; fi
    docker image rm "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
docker info >/dev/null
# The coordinator is based on the official Go image. Every SDK is executed in
# its own official runtime image; no SDK uses these coordinator tools at runtime.
printf '%s\n' 'FROM golang:1.26-alpine' 'RUN apk add --no-cache python3 docker-cli' |
    docker build -q -t "$image" - >/dev/null
# Stream selected source; never copy .env, runtime data, .git, or host credentials.
# Docker uses its own daemon socket inside the VM, so no working-directory bind
# mounts are needed (including on Colima/external volumes).
set +e
COPYFILE_DISABLE=1 tar --exclude='.git' --exclude='.env' --exclude='.env.*' --exclude='data' --exclude='backups' --exclude='master.key' --exclude='*.db' --exclude='*.db-*' --exclude='*.cache' --exclude='*.lic' --exclude='*.test' --exclude='reports' --exclude='target' --exclude='node_modules' --exclude='__pycache__' --exclude='*.egg-info' --exclude='bin' --exclude='obj' --exclude='out' -cf - server sdk |
    docker run -i --memory=1536m --cpus=2 --network host --name "$session-coordinator" \
    --label "authgo.sdk.session=$session" \
    -e "AUTHGO_SDK_SESSION=$session" \
    -e "AUTHGO_SDK_REPORT_DIR=/reports" \
    -e "AUTHGO_SDK_LANGUAGES=${AUTHGO_SDK_LANGUAGES:-}" \
    -v /var/run/docker.sock:/var/run/docker.sock -v "$prefix-gomod":/go/pkg/mod -v "$prefix-gocache":/root/.cache/go-build -w /work "$image" \
    sh -c 'tar -xf -; exec python3 sdk/conformance/run.py'

result=$?
set -e
reports="sdk/conformance/reports/$session"
mkdir -p "$reports"
for name in go python node java csharp php rust build host; do
    docker cp "$session-coordinator:/reports/$name.log" "$reports/$name.log" 2>/dev/null || true
done
docker cp "$session-coordinator:/reports/results.json" "$reports/results.json" 2>/dev/null || true
printf 'SDK reports: %s\n' "$reports"
exit "$result"
