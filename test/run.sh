#!/usr/bin/env bash
# slap test runner — single entry point for all tests
# Usage: ./test/run.sh [path-to-slap-binary] [filter]
#
# Examples:
#   ./test/run.sh                          # run all tests
#   ./test/run.sh "" convert               # run tests matching "convert"
#   ./test/run.sh "" stadium2              # run tests matching "stadium2"
#   ./test/run.sh "" ninja1               # run tests matching "ninja1"
set -uo pipefail
shopt -s globstar nullglob

SLAP="${1:-$(find dist-newstyle -name slap -type f 2>/dev/null | head -1)}"
if [ ! -x "$SLAP" ]; then
  echo "slap binary not found. Build first or pass path as argument."
  exit 1
fi
export SLAP

FILTER="${2:-}"
export FILTER

REPO="$(cd "$(dirname "$0")/.." && pwd)"
export REPO

# Source shared helpers
source "$REPO/test/lib.sh"

echo "slap test suite"
echo "binary: $SLAP"
echo ""

# Discover and run test modules in numeric order
for module in "$REPO"/test/tests/[0-9]*.sh; do
  [ -f "$module" ] || continue
  source "$module"
done

echo "=============================="
echo "passed: $pass  failed: $fail  skipped: $skip"
[ "$fail" -eq 0 ] || exit 1
