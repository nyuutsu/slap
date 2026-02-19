#!/usr/bin/env bash
# slap round-trip test harness — validates create, undo, convert, info, explain
# Usage: ./test/roundtrip.sh [path-to-slap-binary] [filter]
#
# Each scenario applies a known-good BPS patch to generate a target,
# then round-trips through all compatible create formats.
set -euo pipefail

SLAP="${1:-$(find dist-newstyle -name slap -type f 2>/dev/null | head -1)}"
if [ ! -x "$SLAP" ]; then
  echo "slap binary not found. Build first or pass path as argument."
  exit 1
fi

FILTER="${2:-}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

pass=0
fail=0
skip=0

# Temp file management
TMPFILES=()
cleanup() { rm -f "${TMPFILES[@]}"; }
trap cleanup EXIT
mktmp() { local f; f=$(mktemp); TMPFILES+=("$f"); echo "$f"; }

ok()   { echo "OK    $1"; ((pass++)) || true; }
bad()  { echo "FAIL  $1 — $2"; ((fail++)) || true; }
skp()  { echo "SKIP  $1 — $2"; ((skip++)) || true; }

############################################################################
# Test functions
############################################################################

# test_create <label> <base> <target> <target_sha> <format>
# Creates a patch from (base, target), applies it to base, verifies SHA256.
test_create() {
  local label="$1" base="$2" target="$3" target_sha="$4" fmt="$5"
  local name="create-$fmt ($label)"
  local patch; patch=$(mktmp)
  local result; result=$(mktmp)

  if ! "$SLAP" create --format "$fmt" "$base" "$target" "$patch" >/dev/null 2>&1; then
    bad "$name" "create failed"
    return
  fi

  cp "$base" "$result"
  if ! "$SLAP" apply "$patch" "$result" --in-place --no-backup >/dev/null 2>&1; then
    bad "$name" "apply of created patch failed"
    return
  fi

  local got_sha
  got_sha=$(sha256sum "$result" | cut -d' ' -f1)
  if [ "$got_sha" = "$target_sha" ]; then
    ok "$name"
  else
    bad "$name" "SHA256 mismatch"
  fi
}

# test_undo <label> <base> <base_sha> <patch> <format>
# Applies a patch, then undoes it, verifying we get back to original.
test_undo() {
  local label="$1" base="$2" base_sha="$3" patch="$4" fmt="$5"
  local name="undo-$fmt ($label)"
  local work; work=$(mktmp)

  cp "$base" "$work"
  if ! "$SLAP" apply "$patch" "$work" --in-place --no-backup --force >/dev/null 2>&1; then
    bad "$name" "apply failed"
    return
  fi

  if ! "$SLAP" undo "$patch" "$work" >/dev/null 2>&1; then
    bad "$name" "undo failed"
    return
  fi

  local got_sha
  got_sha=$(sha256sum "$work" | cut -d' ' -f1)
  if [ "$got_sha" = "$base_sha" ]; then
    ok "$name"
  else
    bad "$name" "SHA256 mismatch after undo"
  fi
}

# test_undo_created <label> <base> <base_sha> <target> <format>
# Creates a patch with undo data, applies, then undoes.
test_undo_created() {
  local label="$1" base="$2" base_sha="$3" target="$4" fmt="$5"
  local name="undo-$fmt ($label)"
  local patch; patch=$(mktmp)
  local work; work=$(mktmp)

  local create_args=("--format" "$fmt")
  if [ "$fmt" = "ppf3" ]; then
    create_args+=("--undo")
  fi

  if ! "$SLAP" create "${create_args[@]}" "$base" "$target" "$patch" >/dev/null 2>&1; then
    bad "$name" "create failed"
    return
  fi

  cp "$base" "$work"
  if ! "$SLAP" apply "$patch" "$work" --in-place --no-backup --force >/dev/null 2>&1; then
    bad "$name" "apply failed"
    return
  fi

  if ! "$SLAP" undo "$patch" "$work" >/dev/null 2>&1; then
    bad "$name" "undo failed"
    return
  fi

  local got_sha
  got_sha=$(sha256sum "$work" | cut -d' ' -f1)
  if [ "$got_sha" = "$base_sha" ]; then
    ok "$name"
  else
    bad "$name" "SHA256 mismatch after undo"
  fi
}

# test_convert <label> <base> <patch> <target_sha> <to_fmt> [extra_args...]
# Converts patch to target format, applies converted, verifies SHA256.
test_convert() {
  local label="$1" base="$2" patch="$3" target_sha="$4" to_fmt="$5"
  shift 5
  local name="convert-to-$to_fmt ($label)"
  local converted; converted=$(mktmp)
  local result; result=$(mktmp)

  local convert_args=("$patch" "--to" "$to_fmt" "-o" "$converted")
  # Remaining args passed through (--with, --no-undo, --no-validate, etc.)
  convert_args+=("$@")

  if ! "$SLAP" convert "${convert_args[@]}" >/dev/null 2>&1; then
    bad "$name" "convert failed"
    return
  fi

  cp "$base" "$result"
  if ! "$SLAP" apply "$converted" "$result" --in-place --no-backup --force >/dev/null 2>&1; then
    bad "$name" "apply of converted patch failed"
    return
  fi

  local got_sha
  got_sha=$(sha256sum "$result" | cut -d' ' -f1)
  if [ "$got_sha" = "$target_sha" ]; then
    ok "$name"
  else
    bad "$name" "SHA256 mismatch"
  fi
}

# test_smoke <label> <patch>
# Verifies info and explain don't crash.
test_smoke() {
  local label="$1" patch="$2"

  local name="info ($label)"
  if "$SLAP" info "$patch" >/dev/null 2>&1; then
    ok "$name"
  else
    bad "$name" "info crashed"
  fi

  name="explain ($label)"
  if "$SLAP" explain "$patch" >/dev/null 2>&1; then
    ok "$name"
  else
    bad "$name" "explain crashed"
  fi
}

############################################################################
# Bootstrap: apply a BPS patch to generate the target for round-tripping
############################################################################

bootstrap() {
  local base="$1" bps_patch="$2"
  local target; target=$(mktmp)
  cp "$base" "$target"
  if ! "$SLAP" apply "$bps_patch" "$target" --in-place --no-backup >/dev/null 2>&1; then
    echo "FATAL: bootstrap apply failed for $bps_patch"
    exit 1
  fi
  echo "$target"
}

############################################################################
# Scenarios
############################################################################

run_dm4k() {
  [[ -z "$FILTER" || "dm4k" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local bps="$REPO/test/data/dm4k/patch.bps"
  [ -f "$base" ] || { skp "dm4k" "base ROM not found"; return; }

  echo "--- dm4k round-trip (4 MB GBC) ---"

  local target; target=$(bootstrap "$base" "$bps")
  local target_sha; target_sha=$(sha256sum "$target" | cut -d' ' -f1)
  local base_sha; base_sha=$(sha256sum "$base" | cut -d' ' -f1)

  # Create round-trips
  for fmt in bps ips ips32 ups ppf3 pmsr; do
    test_create "dm4k" "$base" "$target" "$target_sha" "$fmt"
  done

  # Undo: UPS (self-inverse via existing patch)
  test_undo "dm4k" "$base" "$base_sha" "$REPO/test/data/dm4k/patch.ups" ups

  # Undo: PPF3 (create with --undo, then undo)
  test_undo_created "dm4k" "$base" "$base_sha" "$target" ppf3

  # Convert: IPS → IPS32 (direct)
  test_convert "dm4k ips→ips32" "$base" "$REPO/test/data/dm4k/patch.ips" "$target_sha" ips32

  # Convert: IPS32 → IPS (direct)
  test_convert "dm4k ips32→ips" "$base" "$REPO/test/data/dm4k/patch.ips32" "$target_sha" ips

  # Direct overlay conversions (no --with needed)
  test_convert "dm4k ppf→ips" "$base" "$REPO/test/data/dm4k/patch.ppf" "$target_sha" ips
  test_convert "dm4k ips→ppf3 (no-undo)" "$base" "$REPO/test/data/dm4k/patch.ips" "$target_sha" ppf3 --no-undo --no-validate
  test_convert "dm4k ips→ninja1" "$base" "$REPO/test/data/dm4k/patch.ips" "$target_sha" ninja1
  test_convert "dm4k ips→pmsr" "$base" "$REPO/test/data/dm4k/patch.ips" "$target_sha" pmsr
  test_convert "dm4k ips→ips32 (overlay)" "$base" "$REPO/test/data/dm4k/patch.ips" "$target_sha" ips32
  test_convert "dm4k ppf→ppf3 (with-val)" "$base" "$REPO/test/data/dm4k/patch.ppf" "$target_sha" ppf3

  # Smoke: info + explain on BPS
  test_smoke "dm4k bps" "$bps"

  echo ""
}

run_emerald_heavy() {
  [[ -z "$FILTER" || "emerald-heavy" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/emerald/base.gba"
  local bps="$REPO/test/data/emerald/heavy-diff/patch.bps"
  [ -f "$base" ] || { skp "emerald-heavy" "base ROM not found"; return; }

  echo "--- emerald heavy-diff round-trip (16 MB GBA) ---"

  local target; target=$(bootstrap "$base" "$bps")
  local target_sha; target_sha=$(sha256sum "$target" | cut -d' ' -f1)
  local base_sha; base_sha=$(sha256sum "$base" | cut -d' ' -f1)

  for fmt in bps ips ips32 ups ppf3 pmsr; do
    test_create "emerald-heavy" "$base" "$target" "$target_sha" "$fmt"
  done

  test_undo "emerald-heavy" "$base" "$base_sha" "$REPO/test/data/emerald/heavy-diff/patch.ups" ups
  test_undo_created "emerald-heavy" "$base" "$base_sha" "$target" ppf3

  test_convert "emerald-heavy ips→ips32" "$base" "$REPO/test/data/emerald/heavy-diff/patch.ips" "$target_sha" ips32
  test_convert "emerald-heavy ips32→ips" "$base" "$REPO/test/data/emerald/heavy-diff/patch.ips32" "$target_sha" ips

  test_smoke "emerald-heavy bps" "$bps"

  echo ""
}

run_emerald_rle() {
  [[ -z "$FILTER" || "emerald-rle" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/emerald/base.gba"
  local bps="$REPO/test/data/emerald/rle/patch.bps"
  [ -f "$base" ] || { skp "emerald-rle" "base ROM not found"; return; }

  echo "--- emerald rle round-trip (16 MB GBA) ---"

  local target; target=$(bootstrap "$base" "$bps")
  local target_sha; target_sha=$(sha256sum "$target" | cut -d' ' -f1)
  local base_sha; base_sha=$(sha256sum "$base" | cut -d' ' -f1)

  for fmt in bps ips ips32 ups ppf3 pmsr; do
    test_create "emerald-rle" "$base" "$target" "$target_sha" "$fmt"
  done

  test_undo "emerald-rle" "$base" "$base_sha" "$REPO/test/data/emerald/rle/patch.ups" ups
  test_undo_created "emerald-rle" "$base" "$base_sha" "$target" ppf3

  test_convert "emerald-rle ips→ips32" "$base" "$REPO/test/data/emerald/rle/patch.ips" "$target_sha" ips32
  test_convert "emerald-rle ips32→ips" "$base" "$REPO/test/data/emerald/rle/patch.ips32" "$target_sha" ips

  test_smoke "emerald-rle bps" "$bps"

  echo ""
}

run_emerald_size() {
  [[ -z "$FILTER" || "emerald-size" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/emerald/base.gba"
  local bps="$REPO/test/data/emerald/size-change/patch.bps"
  [ -f "$base" ] || { skp "emerald-size" "base ROM not found"; return; }

  echo "--- emerald size-change round-trip (16 → 32 MB) ---"

  local target; target=$(bootstrap "$base" "$bps")
  local target_sha; target_sha=$(sha256sum "$target" | cut -d' ' -f1)
  local base_sha; base_sha=$(sha256sum "$base" | cut -d' ' -f1)

  # Only formats that support size change
  for fmt in bps ups; do
    test_create "emerald-size" "$base" "$target" "$target_sha" "$fmt"
  done

  # UPS undo skipped: self-inverse only works with same-size files

  test_smoke "emerald-size bps" "$bps"

  echo ""
}

run_stadium2_heavy() {
  [[ -z "$FILTER" || "stadium2-heavy" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/stadium2/base.z64"
  local bps="$REPO/test/data/stadium2/heavy-diff/patch.bps"
  [ -f "$base" ] || { skp "stadium2-heavy" "base ROM not found"; return; }

  echo "--- stadium2 heavy-diff round-trip (64 MB N64) ---"

  local target; target=$(bootstrap "$base" "$bps")
  local target_sha; target_sha=$(sha256sum "$target" | cut -d' ' -f1)
  local base_sha; base_sha=$(sha256sum "$base" | cut -d' ' -f1)

  # No IPS (64 MB > 16 MB limit)
  for fmt in bps ips32 ups ppf3 pmsr; do
    test_create "stadium2-heavy" "$base" "$target" "$target_sha" "$fmt"
  done

  test_undo "stadium2-heavy" "$base" "$base_sha" "$REPO/test/data/stadium2/heavy-diff/patch.ups" ups
  test_undo_created "stadium2-heavy" "$base" "$base_sha" "$target" ppf3

  test_smoke "stadium2-heavy bps" "$bps"

  echo ""
}

run_stadium2_rle() {
  [[ -z "$FILTER" || "stadium2-rle" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/stadium2/base.z64"
  local bps="$REPO/test/data/stadium2/rle/patch.bps"
  [ -f "$base" ] || { skp "stadium2-rle" "base ROM not found"; return; }

  echo "--- stadium2 rle round-trip (64 MB N64) ---"

  local target; target=$(bootstrap "$base" "$bps")
  local target_sha; target_sha=$(sha256sum "$target" | cut -d' ' -f1)
  local base_sha; base_sha=$(sha256sum "$base" | cut -d' ' -f1)

  for fmt in bps ips32 ups ppf3 pmsr; do
    test_create "stadium2-rle" "$base" "$target" "$target_sha" "$fmt"
  done

  test_undo "stadium2-rle" "$base" "$base_sha" "$REPO/test/data/stadium2/rle/patch.ups" ups
  test_undo_created "stadium2-rle" "$base" "$base_sha" "$target" ppf3

  test_smoke "stadium2-rle bps" "$bps"

  echo ""
}

run_stadium2_size() {
  [[ -z "$FILTER" || "stadium2-size" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/stadium2/base.z64"
  local bps="$REPO/test/data/stadium2/size-change/patch.bps"
  [ -f "$base" ] || { skp "stadium2-size" "base ROM not found"; return; }

  echo "--- stadium2 size-change round-trip (64 → 128 MB) ---"

  local target; target=$(bootstrap "$base" "$bps")
  local target_sha; target_sha=$(sha256sum "$target" | cut -d' ' -f1)
  local base_sha; base_sha=$(sha256sum "$base" | cut -d' ' -f1)

  for fmt in bps ups; do
    test_create "stadium2-size" "$base" "$target" "$target_sha" "$fmt"
  done

  # UPS undo skipped: self-inverse only works with same-size files

  test_smoke "stadium2-size bps" "$bps"

  echo ""
}

run_papermario_mod() {
  [[ -z "$FILTER" || "papermario-mod" == *"$FILTER"* ]] || return 0
  local mod1="$REPO/test/data/paper-mario/pmmq-jr.mod"
  local mod2="$REPO/test/data/paper-mario/paper-parable.mod"
  [ -f "$mod1" ] || { skp "papermario-mod" ".mod files not found"; return; }

  echo "--- paper-mario PMSR/Yay0 smoke tests ---"

  test_smoke "pmmq-jr.mod" "$mod1"
  test_smoke "paper-parable.mod" "$mod2"

  echo ""
}

############################################################################
# Main
############################################################################

echo "slap round-trip test suite"
echo "binary: $SLAP"
echo ""

run_dm4k
run_emerald_heavy
run_emerald_rle
run_emerald_size
run_stadium2_heavy
run_stadium2_rle
run_stadium2_size
run_papermario_mod

echo "passed: $pass  failed: $fail  skipped: $skip"
[ "$fail" -eq 0 ] || exit 1
