#!/bin/sh
#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GO=${GO:-/usr/local/go/bin/go}
TEST_P=${MCPX_TEST_P:-4}
RACE_P=${MCPX_RACE_P:-2}

if [ ! -x "$GO" ]; then
  GO=$(command -v go)
fi
GOFMT=${GOFMT:-$(dirname "$GO")/gofmt}
if [ ! -x "$GOFMT" ]; then
  GOFMT=$(command -v gofmt)
fi

check_format() {
  root=$1
  unformatted=$(find "$root/cmd" "$root/internal" -type f -name '*.go' -print0 | xargs -0 "$GOFMT" -l)
  if [ -n "$unformatted" ]; then
    printf '%s\n' "unformatted Go files under $root:" >&2
    printf '%s\n' "$unformatted" >&2
    exit 1
  fi
}

cd "$ROOT"
printf '%s\n' '[mcpx] format check'
check_format "$ROOT"

printf '%s\n' '[mcpx] full tests'
$GO test -p "$TEST_P" ./... -count=1
printf '%s\n' '[mcpx] race: hot paths'
$GO test -race -p "$RACE_P" ./internal/source ./internal/changeset ./internal/server ./internal/state ./internal/terminal -count=1
printf '%s\n' '[mcpx] vet + release build'
$GO vet ./...
CGO_ENABLED=0 $GO build -trimpath -o bin/mcpx-server-verify ./cmd/mcpx-server

GATEWAY="$ROOT/../mcpx-remote-gateway"
if [ -d "$GATEWAY" ]; then
  printf '%s\n' '[gateway] format check'
  check_format "$GATEWAY"
  printf '%s\n' '[gateway] full tests'
  $GO -C "$GATEWAY" test ./... -count=1
  printf '%s\n' '[gateway] race: relay hot paths'
  $GO -C "$GATEWAY" test -race ./internal/agent ./internal/hub -count=1
  printf '%s\n' '[gateway] vet + release build'
  $GO -C "$GATEWAY" vet ./...
  CGO_ENABLED=0 $GO -C "$GATEWAY" build -trimpath -o bin/mcpx-agent-verify ./cmd/mcpx-agent
fi

if [ "${MCPX_BENCH:-0}" = "1" ]; then
  printf '%s\n' '[mcpx] web-mac performance samples'
  $GO test ./internal/source ./internal/changeset -run '^$' -bench BenchmarkPerformance -benchmem -benchtime=10x -count=1
fi

printf '%s\n' 'web-mac verification passed'
