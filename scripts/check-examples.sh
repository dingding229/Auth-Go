#!/bin/sh
# Called by CI and other test runners; run from the repository root.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test -f "$ROOT/examples/basic/go.mod"
find "$ROOT/examples" -name go.mod -not -path '*/vendor/*' -not -path '*/node_modules/*' | sort | while IFS= read -r module; do
  directory=$(dirname "$module")
  printf 'Checking examples module: %s\n' "${directory#"$ROOT/"}"
  (
    cd "$directory"
    output=$(mktemp -d)
    generated_padding=false
    cleanup() { rm -rf "$output"; if [ "$generated_padding" = true ]; then rm -f padding.bin; fi; }
    trap cleanup EXIT HUP INT TERM
    # This program intentionally embeds 100 MiB, just like its Docker build.
    if [ "$directory" = "$ROOT/examples/docker-protected/go" ] && [ ! -f padding.bin ]; then
      generated_padding=true
      dd if=/dev/zero of=padding.bin bs=1048576 count=100 2>/dev/null
    fi
    go build -o "$output/" ./...
    go vet ./...
    go test ./...
  )
done
