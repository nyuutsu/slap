#!/usr/bin/env bash
# slap test runner — discovers .suite manifests and verifies all patches
# Usage: ./test/run.sh [path-to-slap-binary] [suite-glob]
#
# Examples:
#   ./test/run.sh                          # run all suites
#   ./test/run.sh "" dm4k                  # run only suites matching "dm4k"
#   ./test/run.sh "" emerald               # run suites matching "emerald"
set -euo pipefail

SLAP="${1:-$(find dist-newstyle -name slap -type f 2>/dev/null | head -1)}"
if [ ! -x "$SLAP" ]; then
  echo "slap binary not found. Build first or pass path as argument."
  exit 1
fi

FILTER="${2:-}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SUITE_DIR="$REPO/test/suites"

pass=0
fail=0
skip=0
broken_skip=0

run_suite() {
  local suite_file="$1"
  local suite_name
  suite_name=$(basename "$suite_file" .suite)

  # Filter if requested
  if [ -n "$FILTER" ] && [[ "$suite_name" != *"$FILTER"* ]]; then
    return
  fi

  local base="" sha256="" desc=""

  # Parse header
  while IFS= read -r line; do
    line="${line%%#*}"             # strip comments
    [[ -z "${line// /}" ]] && continue  # skip blank
    case "$line" in
      base:*)   base="${line#base:}";     base="$(echo "$base" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" ;;
      sha256:*) sha256="${line#sha256:}";  sha256="$(echo "$sha256" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" ;;
      desc:*)   desc="${line#desc:}";      desc="$(echo "$desc" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" ;;
      *"|"*)    break ;;                   # hit patch lines
    esac
  done < "$suite_file"

  if [ -z "$base" ] || [ -z "$sha256" ]; then
    echo "SKIP  [$suite_name] — missing base or sha256 in manifest"
    ((skip++)) || true
    return
  fi

  local base_path="$REPO/$base"
  if [ ! -f "$base_path" ]; then
    echo "SKIP  [$suite_name] — base ROM not found: $base"
    ((skip++)) || true
    return
  fi

  echo "--- $desc ---"

  # Parse and run each patch line
  while IFS= read -r line; do
    line="${line%%#*}"
    [[ -z "${line// /}" ]] && continue
    # Skip header lines
    case "$line" in
      base:*|sha256:*|desc:*) continue ;;
    esac

    # Parse: FORMAT | PATH | CONFIDENCE | PROVENANCE
    IFS='|' read -r fmt path confidence provenance <<< "$line"
    fmt="$(echo "$fmt" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    path="$(echo "$path" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    confidence="$(echo "$confidence" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    provenance="$(echo "$provenance" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

    local test_name="$fmt"
    local patch_path="$REPO/$path"

    # Skip broken patches
    if [ "$confidence" = "broken" ]; then
      echo "SKIP  $test_name — broken ($provenance)"
      ((broken_skip++)) || true
      continue
    fi

    # Skip untested patches (note them but don't fail)
    if [ "$confidence" = "untested" ]; then
      if [ ! -f "$patch_path" ]; then
        echo "SKIP  $test_name — untested, file missing"
        ((skip++)) || true
        continue
      fi
    fi

    if [ ! -f "$patch_path" ]; then
      echo "SKIP  $test_name — patch not found: $path"
      ((skip++)) || true
      continue
    fi

    local tmp
    tmp=$(mktemp)
    cp "$base_path" "$tmp"
    if "$SLAP" apply "$patch_path" "$tmp" --in-place --no-backup >/dev/null 2>&1; then
      local got_sha
      got_sha=$(sha256sum "$tmp" | cut -d' ' -f1)
      if [ "$got_sha" = "$sha256" ]; then
        echo "OK    $test_name"
        ((pass++)) || true
      else
        echo "FAIL  $test_name — SHA256 mismatch"
        ((fail++)) || true
      fi
    else
      echo "FAIL  $test_name — slap apply returned error"
      ((fail++)) || true
    fi
    rm -f "$tmp"
  done < "$suite_file"
  echo ""
}

echo "slap test suite"
echo "binary: $SLAP"
echo ""

for suite in "$SUITE_DIR"/*.suite; do
  [ -f "$suite" ] || continue
  run_suite "$suite"
done

echo "passed: $pass  failed: $fail  skipped: $skip  broken: $broken_skip"
[ "$fail" -eq 0 ] || exit 1
