#!/bin/sh
# Run from the repository root. Verify observable export side effects survive
# ordinary Go test cache reuse; no helper changes or backend aliases required.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
for pass in 1 2 3; do
  rm -f server/.route-contract.json
  (cd server && go test ./internal/httpserver -run '^TestExportFrontendRouteContract$')
  test -s server/.route-contract.json || {
    echo "route-contract cache regression: export missing after pass $pass" >&2
    exit 1
  }
  printf 'route-contract-cache pass=%s regenerated=yes\n' "$pass"
done
