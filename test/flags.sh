#!/usr/bin/env bash
# slap flag & error path tests — validates CLI behavior, flag combinations,
# error messages, and edge cases.
# Usage: ./test/flags.sh [path-to-slap-binary] [filter]
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

TMPFILES=()
cleanup() { rm -f "${TMPFILES[@]}"; }
trap cleanup EXIT
mktmp() { local f; f=$(mktemp); TMPFILES+=("$f"); echo "$f"; }

ok()   { echo "OK    $1"; ((pass++)) || true; }
bad()  { echo "FAIL  $1 — $2"; ((fail++)) || true; }
skp()  { echo "SKIP  $1 — $2"; ((skip++)) || true; }

# Expect a command to fail (nonzero exit) and stderr to contain a substring.
expect_fail() {
  local name="$1" pattern="$2"
  shift 2
  local out
  if out=$("$@" 2>&1); then
    bad "$name" "expected failure but got success"
    return
  fi
  if echo "$out" | grep -qi "$pattern"; then
    ok "$name"
  else
    bad "$name" "expected '$pattern' in output, got: $out"
  fi
}

# Expect a command to succeed and stdout+stderr to contain a substring.
expect_ok() {
  local name="$1" pattern="$2"
  shift 2
  local out
  if ! out=$("$@" 2>&1); then
    bad "$name" "expected success but got failure: $out"
    return
  fi
  if echo "$out" | grep -qi "$pattern"; then
    ok "$name"
  else
    bad "$name" "expected '$pattern' in output, got: $out"
  fi
}

# Expect a command to succeed (don't check output).
expect_success() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    ok "$name"
  else
    bad "$name" "command failed"
  fi
}

############################################################################
# Corrupt / invalid input
############################################################################

run_corrupt() {
  [[ -z "$FILTER" || "corrupt" == *"$FILTER"* ]] || return 0
  echo "--- corrupt / invalid input ---"

  # Empty file
  local empty; empty=$(mktmp)
  : > "$empty"
  expect_fail "info empty file" "unknown" "$SLAP" info "$empty"
  expect_fail "explain empty file" "unknown" "$SLAP" explain "$empty"

  # Random garbage
  local garbage; garbage=$(mktmp)
  dd if=/dev/urandom of="$garbage" bs=256 count=1 2>/dev/null
  expect_fail "info random garbage" "unknown" "$SLAP" info "$garbage"

  # IPS parser is tolerant: "PATCH" + garbage parses as 0 records.
  # Verify it doesn't crash (graceful degradation, not an error).
  local trunc; trunc=$(mktmp)
  printf 'PATCH\x01\x02' > "$trunc"
  expect_ok "info truncated IPS (graceful)" "0" "$SLAP" info "$trunc"

  # Truncated BPS (valid magic, no content)
  local trunc_bps; trunc_bps=$(mktmp)
  printf 'BPS1' > "$trunc_bps"
  expect_fail "info truncated BPS" "" "$SLAP" info "$trunc_bps"

  echo ""
}

############################################################################
# --dry-run
############################################################################

run_dryrun() {
  [[ -z "$FILTER" || "dryrun" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local patch="$REPO/test/data/dm4k/patch.bps"
  [ -f "$base" ] || { skp "dryrun" "base ROM not found"; return; }

  echo "--- --dry-run ---"

  # --dry-run should print "would apply" and not create output
  local out; out=$(mktmp)
  rm -f "$out"
  expect_ok "dry-run reports action" "would apply" \
    "$SLAP" apply "$patch" "$base" -o "$out" --dry-run
  if [ -f "$out" ]; then
    bad "dry-run no output file" "output file was created"
  else
    ok "dry-run no output file"
  fi

  # --dry-run with CRC-bearing format shows CRC status
  expect_ok "dry-run shows CRC" "source CRC" \
    "$SLAP" apply "$patch" "$base" --dry-run

  # --dry-run + --in-place should NOT modify source
  local work; work=$(mktmp)
  cp "$base" "$work"
  local before_sha; before_sha=$(sha256sum "$work" | cut -d' ' -f1)
  "$SLAP" apply "$patch" "$work" --in-place --no-backup --dry-run >/dev/null 2>&1 || true
  local after_sha; after_sha=$(sha256sum "$work" | cut -d' ' -f1)
  if [ "$before_sha" = "$after_sha" ]; then
    ok "dry-run + in-place leaves source untouched"
  else
    bad "dry-run + in-place leaves source untouched" "source was modified"
  fi

  echo ""
}

############################################################################
# --force (CRC mismatch override)
############################################################################

run_force() {
  [[ -z "$FILTER" || "force" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local patch="$REPO/test/data/dm4k/patch.ups"
  [ -f "$base" ] || { skp "force" "base ROM not found"; return; }

  echo "--- --force (CRC mismatch) ---"

  # Apply a UPS patch to wrong source (random file) — should fail without --force
  local wrong; wrong=$(mktmp)
  dd if=/dev/urandom of="$wrong" bs=4096 count=1024 2>/dev/null
  local crc_out; crc_out=$(mktmp)
  rm -f "$crc_out"
  expect_fail "UPS wrong source fails" "CRC mismatch" \
    "$SLAP" apply "$patch" "$wrong" -o "$crc_out"

  # Same with --force should succeed (or at least not die on CRC)
  local out; out=$(mktmp)
  rm -f "$out"
  expect_ok "UPS wrong source + --force" "applied" \
    "$SLAP" apply "$patch" "$wrong" -o "$out" --force

  echo ""
}

############################################################################
# --in-place + --no-backup
############################################################################

run_inplace() {
  [[ -z "$FILTER" || "inplace" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local patch="$REPO/test/data/dm4k/patch.ips"
  [ -f "$base" ] || { skp "inplace" "base ROM not found"; return; }

  echo "--- --in-place flag combinations ---"

  # --in-place creates .bak by default
  local work; work=$(mktmp)
  cp "$base" "$work"
  "$SLAP" apply "$patch" "$work" --in-place >/dev/null 2>&1
  if [ -f "${work}.bak" ]; then
    ok "in-place creates .bak"
    rm -f "${work}.bak"
  else
    bad "in-place creates .bak" "no .bak created"
  fi

  # --in-place --no-backup does NOT create .bak
  cp "$base" "$work"
  "$SLAP" apply "$patch" "$work" --in-place --no-backup >/dev/null 2>&1
  if [ -f "${work}.bak" ]; then
    bad "in-place --no-backup skips .bak" ".bak was created"
    rm -f "${work}.bak"
  else
    ok "in-place --no-backup skips .bak"
  fi

  echo ""
}

############################################################################
# Output file collision
############################################################################

run_collision() {
  [[ -z "$FILTER" || "collision" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local patch="$REPO/test/data/dm4k/patch.ips"
  [ -f "$base" ] || { skp "collision" "base ROM not found"; return; }

  echo "--- output collision ---"

  # Refuse to overwrite existing output without --force
  local out; out=$(mktmp)
  echo "existing" > "$out"
  expect_fail "overwrite refused without --force" "already exists" \
    "$SLAP" apply "$patch" "$base" -o "$out"

  # --force allows overwrite
  expect_ok "overwrite allowed with --force" "applied" \
    "$SLAP" apply "$patch" "$base" -o "$out" --force

  echo ""
}

############################################################################
# --verbose
############################################################################

run_verbose() {
  [[ -z "$FILTER" || "verbose" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local patch="$REPO/test/data/dm4k/patch.ips"
  [ -f "$base" ] || { skp "verbose" "base ROM not found"; return; }

  echo "--- --verbose ---"

  local out; out=$(mktmp)
  # --verbose should print per-record lines
  expect_ok "verbose prints records" "\\[1/" \
    "$SLAP" apply "$patch" "$base" -o "$out" --verbose --force

  echo ""
}

############################################################################
# Undo error paths
############################################################################

run_undo_errors() {
  [[ -z "$FILTER" || "undo" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local ips_patch="$REPO/test/data/dm4k/patch.ips"
  [ -f "$base" ] || { skp "undo" "base ROM not found"; return; }

  echo "--- undo error paths ---"

  # Undo on a format that doesn't support it (IPS) should fail
  expect_fail "undo unsupported (IPS)" "undo not supported" \
    "$SLAP" undo "$ips_patch" "$base"

  # Undo on BPS should fail
  local bps_patch="$REPO/test/data/dm4k/patch.bps"
  expect_fail "undo unsupported (BPS)" "undo not supported" \
    "$SLAP" undo "$bps_patch" "$base"

  echo ""
}

############################################################################
# Convert error paths
############################################################################

run_convert_errors() {
  [[ -z "$FILTER" || "convert" == *"$FILTER"* ]] || return 0
  local bps_patch="$REPO/test/data/dm4k/patch.bps"
  [ -f "$bps_patch" ] || { skp "convert" "patch not found"; return; }

  echo "--- convert error paths ---"

  # BPS → IPS without --with should fail (needs source ROM)
  expect_fail "convert BPS→IPS without --with" "requires the original ROM" \
    "$SLAP" convert "$bps_patch" --to ips

  echo ""
}

############################################################################
# Compound flag paths
############################################################################

run_compound() {
  [[ -z "$FILTER" || "compound" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local bps_patch="$REPO/test/data/dm4k/patch.bps"
  local ips_patch="$REPO/test/data/dm4k/patch.ips"
  [ -f "$base" ] || { skp "compound" "base ROM not found"; return; }

  echo "--- compound flag combinations ---"

  # --in-place + --force + --verbose + --no-backup (InPlace strategy, IPS)
  local work; work=$(mktmp)
  cp "$base" "$work"
  expect_ok "in-place+force+verbose+no-backup (IPS)" "applied" \
    "$SLAP" apply "$ips_patch" "$work" --in-place --force --verbose --no-backup

  # Same combo with InMemory strategy (BPS)
  cp "$base" "$work"
  expect_ok "in-place+force+verbose+no-backup (BPS)" "applied" \
    "$SLAP" apply "$bps_patch" "$work" --in-place --force --verbose --no-backup

  # --dry-run + --verbose (should show records AND "would apply")
  local out
  out=$("$SLAP" apply "$ips_patch" "$base" --dry-run --verbose 2>&1) || true
  if echo "$out" | grep -q "would apply" && echo "$out" | grep -q "\[1/"; then
    ok "dry-run+verbose shows both"
  else
    bad "dry-run+verbose shows both" "missing expected output"
  fi

  # --dry-run + --force (should still just report, not apply)
  work=$(mktmp)
  cp "$base" "$work"
  local before_sha; before_sha=$(sha256sum "$work" | cut -d' ' -f1)
  "$SLAP" apply "$bps_patch" "$work" --in-place --dry-run --force >/dev/null 2>&1 || true
  local after_sha; after_sha=$(sha256sum "$work" | cut -d' ' -f1)
  if [ "$before_sha" = "$after_sha" ]; then
    ok "dry-run+force doesn't modify"
  else
    bad "dry-run+force doesn't modify" "source was modified"
  fi

  # -o explicit output path (not derived)
  local explicit; explicit=$(mktmp)
  rm -f "$explicit"
  expect_ok "explicit -o output" "applied" \
    "$SLAP" apply "$ips_patch" "$base" -o "$explicit"
  if [ -f "$explicit" ]; then
    ok "explicit -o file created"
  else
    bad "explicit -o file created" "file not found"
  fi

  echo ""
}

############################################################################
# Create + validate (PPF3 --validate flag)
############################################################################

run_create_flags() {
  [[ -z "$FILTER" || "create" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local bps="$REPO/test/data/dm4k/patch.bps"
  [ -f "$base" ] || { skp "create" "base ROM not found"; return; }

  echo "--- create flag combinations ---"

  # Bootstrap target
  local target; target=$(mktmp)
  cp "$base" "$target"
  "$SLAP" apply "$bps" "$target" --in-place --no-backup >/dev/null 2>&1

  # PPF3 with --undo --validate --description
  local patch; patch=$(mktmp)
  expect_ok "create ppf3+undo+validate+desc" "wrote" \
    "$SLAP" create --format ppf3 --undo --validate -d "test patch" "$base" "$target" "$patch"

  # Verify the created patch has undo data (info should show it)
  expect_ok "ppf3 undo data present" "undo" \
    "$SLAP" info "$patch"

  echo ""
}

############################################################################
# Hidden aliases
############################################################################

run_aliases() {
  [[ -z "$FILTER" || "aliases" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local patch="$REPO/test/data/dm4k/patch.ips"
  [ -f "$base" ] || { skp "aliases" "base ROM not found"; return; }

  echo "--- hidden aliases ---"

  # --yolo = --force
  local out; out=$(mktmp)
  expect_ok "--yolo alias" "applied" \
    "$SLAP" apply "$patch" "$base" -o "$out" --yolo

  # --send-it = --force
  expect_ok "--send-it alias" "applied" \
    "$SLAP" apply "$patch" "$base" -o "$out" --send-it

  # --clobber = --in-place
  local work; work=$(mktmp)
  cp "$base" "$work"
  expect_ok "--clobber alias" "applied" \
    "$SLAP" apply "$patch" "$work" --clobber --no-backup

  echo ""
}

############################################################################
# Main
############################################################################

echo "slap flag & error path tests"
echo "binary: $SLAP"
echo ""

run_corrupt
run_dryrun
run_force
run_inplace
run_collision
run_verbose
run_undo_errors
run_convert_errors
run_compound
run_create_flags
run_aliases

echo "passed: $pass  failed: $fail  skipped: $skip"
[ "$fail" -eq 0 ] || exit 1
