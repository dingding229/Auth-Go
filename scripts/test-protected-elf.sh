#!/bin/sh
# Standalone protected ELF test.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v docker >/dev/null 2>&1 || { echo '需要 Docker'; exit 2; }
cd "$ROOT"
python3 -c 'import shutil; n=shutil.disk_usage(".").free; print("DISK_FREE_GIB=%.2f" % (n/1024**3)); assert n >= 10*1024**3, "磁盘不足10GB，停止并报告，不清理其他资源"'
docker run --rm --memory=1536m --cpus=2 --name "authgo-protect-build-$$" \
    -v "$ROOT":/src -v authgo-gomod:/go/pkg/mod -v authgo-gocache:/root/.cache/go-build \
    -w /src golang:1.26-alpine sh -c 'apk add --no-cache make >/dev/null && make build-pack test-pack'
python3 scripts/test-protected-elf.py "$@"
