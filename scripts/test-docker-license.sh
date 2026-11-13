#!/bin/sh
# Only named authgo-dockertest-* resources, real containers, no global cleanup.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
if [ "${1:-}" = "protected-scan" ]; then
  exec python3 scripts/test-protected-scan.py --docker-controls
fi
if [ "${1:-}" = "protected" ]; then
  shift
  python3 scripts/test-protected-scan.py --docker-controls
  exec python3 scripts/test-protected-matrix.py "$@"
fi
python3 scripts/test-docker-license.py "$@"
