#!/usr/bin/env bash
# slap test runner — verifies patch apply for each supported format
# Usage: ./test/run.sh [path-to-slap-binary]
set -euo pipefail

SLAP="${1:-$(find dist-newstyle -name slap -type f 2>/dev/null | head -1)}"
if [ ! -x "$SLAP" ]; then
  echo "slap binary not found. Build first or pass path as argument."
  exit 1
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
BASE="$DIR/dm4k/dm4k-base.gbc"
EXPECTED_SHA="e750c0c7ea5dc9f1751c04164ff362cc7eabad60ded46e0ec55b9de92e6c43e8"

pass=0
fail=0
skip=0

test_patch() {
  local name="$1" patch="$2"
  if [ ! -f "$patch" ]; then
    echo "SKIP  $name — patch not found: $patch"
    ((skip++)) || true
    return
  fi
  local tmp
  tmp=$(mktemp)
  cp "$BASE" "$tmp"
  if "$SLAP" apply "$patch" "$tmp" >/dev/null 2>&1; then
    local sha
    sha=$(sha256sum "$tmp" | cut -d' ' -f1)
    if [ "$sha" = "$EXPECTED_SHA" ]; then
      echo "OK    $name"
      ((pass++)) || true
    else
      echo "FAIL  $name — SHA256 mismatch"
      ((fail++)) || true
    fi
  else
    echo "FAIL  $name — slap apply returned error"
    ((fail++)) || true
  fi
  rm -f "$tmp"
}

echo "slap test suite"
echo "binary: $SLAP"
echo "base:   $BASE"
echo ""

# dm4k patch set — all transform dm4k-base.gbc to the same target
test_patch "IPS"          "$DIR/dm4k/dm4k-patch.ips"
test_patch "IPS32"        "$DIR/dm4k/dm4k-patch.ips32"
test_patch "EBP"          "$DIR/dm4k/dm4k-patch.ebp"
test_patch "BPS"          "$DIR/dm4k/dm4k-patch.bps"
test_patch "UPS"          "$DIR/dm4k/dm4k-patch.ups"
test_patch "PPF1"         "$DIR/dm4k/dm4k-patch.ppf1.ppf"
test_patch "PPF2"         "$DIR/dm4k/dm4k-patch.ppf2.ppf"
test_patch "PPF3"         "$DIR/dm4k/dm4k-patch.ppf"
test_patch "VCDIFF"       "$DIR/dm4k/dm4k-patch.vcdiff"
test_patch "bsdiff"       "$DIR/dm4k/dm4k-patch.bsdiff"
test_patch "APS-N64"      "$DIR/dm4k/dm4k-patch.aps"
test_patch "RUP"          "$DIR/dm4k/dm4k-patch.rup"
test_patch "xdelta1"      "$DIR/dm4k/dm4k-patch.xdelta1"
test_patch "GDIFF"        "$DIR/dm4k/dm4k-patch.gdiff"

echo ""
echo "passed: $pass  failed: $fail  skipped: $skip"
[ "$fail" -eq 0 ] || exit 1
