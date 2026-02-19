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
  local ips_patch="$REPO/test/data/dm4k/patch.ips"
  local ips32_patch="$REPO/test/data/dm4k/patch.ips32"
  local ppf_patch="$REPO/test/data/dm4k/patch.ppf"
  [ -f "$bps_patch" ] || { skp "convert" "patch not found"; return; }

  echo "--- convert error paths ---"

  # BPS → IPS without --with should fail (needs source ROM)
  expect_fail "convert BPS→IPS without --with" "requires the original ROM" \
    "$SLAP" convert "$bps_patch" --to ips

  # IPS → BPS without --with should fail (delta target)
  expect_fail "convert IPS→BPS without --with" "requires source" \
    "$SLAP" convert "$ips_patch" --to bps

  # IPS → APS-N64 without --with should fail (no dest_size)
  expect_fail "convert IPS→APS-N64 without --with" "requires target file size" \
    "$SLAP" convert "$ips_patch" --to aps-n64

  # IPS → PPF3 with undo (default) should fail (no undo data)
  expect_fail "convert IPS→PPF3 wants undo" "no undo data" \
    "$SLAP" convert "$ips_patch" --to ppf3 --no-validate

  # IPS → PPF3 with validate (default) should fail (no validation block)
  expect_fail "convert IPS→PPF3 wants validate" "no validation block" \
    "$SLAP" convert "$ips_patch" --to ppf3 --no-undo

  # IPS → PPF3 --no-undo --no-validate should succeed
  local out; out=$(mktmp)
  expect_ok "convert IPS→PPF3 (no-undo no-validate)" "converted" \
    "$SLAP" convert "$ips_patch" --to ppf3 --no-undo --no-validate -o "$out"

  # PPF (with undo+val) → IPS should emit info-loss notes
  out=$(mktmp)
  local conv_out
  conv_out=$("$SLAP" convert "$ppf_patch" --to ips -o "$out" 2>&1)
  if echo "$conv_out" | grep -q "dropping.*CRC32\|dropping.*undo\|dropping.*description\|dropping.*validation"; then
    ok "convert PPF→IPS emits info-loss notes"
  else
    bad "convert PPF→IPS emits info-loss notes" "no info-loss notes in: $conv_out"
  fi

  # Large-offset IPS32 → IPS should fail (offsets > 0xFFFFFF)
  local big_ips32="$REPO/test/data/stadium2/heavy-diff/patch.ips32"
  if [ -f "$big_ips32" ]; then
    expect_fail "convert IPS32→IPS (large offsets)" "offsets > 16 MB" \
      "$SLAP" convert "$big_ips32" --to ips
  else
    skp "convert IPS32→IPS (large offsets)" "stadium2 test data not found"
  fi

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
# Patch health warnings
############################################################################

run_warnings() {
  [[ -z "$FILTER" || "warnings" == *"$FILTER"* ]] || return 0
  echo "--- patch health warnings ---"

  # Truncated IPS (no EOF marker) → warning about missing EOF + empty
  local trunc; trunc=$(mktmp)
  printf 'PATCH\x01\x02' > "$trunc"
  expect_ok "truncated IPS warns no EOF" "no EOF marker" "$SLAP" info "$trunc"
  expect_ok "truncated IPS warns empty" "empty patch" "$SLAP" info "$trunc"

  # Valid IPS with EOF, 0 records → warns empty but NOT about EOF
  printf 'PATCHEOF' > "$trunc"
  local out
  out=$("$SLAP" info "$trunc" 2>&1)
  if echo "$out" | grep -q "empty patch" && ! echo "$out" | grep -q "no EOF"; then
    ok "empty IPS warns empty only (not EOF)"
  else
    bad "empty IPS warns empty only (not EOF)" "unexpected warning pattern: $out"
  fi

  # Normal IPS → no warnings
  out=$("$SLAP" info "$REPO/test/data/dm4k/patch.ips" 2>&1)
  if echo "$out" | grep -q "warning"; then
    bad "normal IPS no warnings" "unexpected warning: $out"
  else
    ok "normal IPS no warnings"
  fi

  echo ""
}

############################################################################
# Empty diff (identical files)
############################################################################

run_empty_diff() {
  [[ -z "$FILTER" || "empty" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  [ -f "$base" ] || { skp "empty-diff" "base ROM not found"; return; }

  echo "--- empty diff (identical files) ---"

  # Create patches from identical files — should produce valid but empty patches
  for fmt in bps ips ips32 ups ppf3 pmsr; do
    local patch; patch=$(mktmp)
    if "$SLAP" create --format "$fmt" "$base" "$base" "$patch" >/dev/null 2>&1; then
      # Apply the empty patch — should produce identical output
      local result; result=$(mktmp)
      cp "$base" "$result"
      if "$SLAP" apply "$patch" "$result" --in-place --no-backup --force >/dev/null 2>&1; then
        local base_sha; base_sha=$(sha256sum "$base" | cut -d' ' -f1)
        local result_sha; result_sha=$(sha256sum "$result" | cut -d' ' -f1)
        if [ "$base_sha" = "$result_sha" ]; then
          ok "empty-diff $fmt"
        else
          bad "empty-diff $fmt" "SHA256 mismatch after applying empty patch"
        fi
      else
        bad "empty-diff $fmt" "apply of empty patch failed"
      fi
    else
      bad "empty-diff $fmt" "create from identical files failed"
    fi
  done

  echo ""
}

############################################################################
# Undo with -o (output redirect)
############################################################################

run_undo_output() {
  [[ -z "$FILTER" || "undo-output" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local ups_patch="$REPO/test/data/dm4k/patch.ups"
  [ -f "$base" ] || { skp "undo-output" "base ROM not found"; return; }

  echo "--- undo with -o output ---"

  # UPS undo with -o should write to output, not modify source
  local work; work=$(mktmp)
  local out; out=$(mktmp)
  cp "$base" "$work"
  "$SLAP" apply "$ups_patch" "$work" --in-place --no-backup --force >/dev/null 2>&1
  local patched_sha; patched_sha=$(sha256sum "$work" | cut -d' ' -f1)

  rm -f "$out"
  "$SLAP" undo "$ups_patch" "$work" -o "$out" >/dev/null 2>&1
  local base_sha; base_sha=$(sha256sum "$base" | cut -d' ' -f1)
  local out_sha; out_sha=$(sha256sum "$out" | cut -d' ' -f1)
  local work_sha; work_sha=$(sha256sum "$work" | cut -d' ' -f1)

  # Output should match original base
  if [ "$out_sha" = "$base_sha" ]; then
    ok "undo -o produces original"
  else
    bad "undo -o produces original" "SHA256 mismatch"
  fi

  # Source should still be patched (not modified)
  if [ "$work_sha" = "$patched_sha" ]; then
    ok "undo -o leaves source untouched"
  else
    bad "undo -o leaves source untouched" "source was modified"
  fi

  echo ""
}

############################################################################
# Archive unwrapping (automated)
############################################################################

run_archive() {
  [[ -z "$FILTER" || "archive" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local patch="$REPO/test/data/dm4k/patch.ips"
  [ -f "$base" ] || { skp "archive" "base ROM not found"; return; }
  command -v zip >/dev/null || { skp "archive" "zip not found"; return; }
  command -v unzip >/dev/null || { skp "archive" "unzip not found"; return; }

  echo "--- archive unwrapping ---"

  # Create a ZIP containing the patch
  local zipfile; zipfile=$(mktmp).zip
  TMPFILES+=("$zipfile")
  (cd "$(dirname "$patch")" && zip -j "$zipfile" "$(basename "$patch")") >/dev/null 2>&1

  # Apply ZIP-wrapped patch
  local result; result=$(mktmp)
  cp "$base" "$result"
  if "$SLAP" apply "$zipfile" "$result" --in-place --no-backup >/dev/null 2>&1; then
    # Compare against direct apply
    local direct; direct=$(mktmp)
    cp "$base" "$direct"
    "$SLAP" apply "$patch" "$direct" --in-place --no-backup >/dev/null 2>&1
    local zip_sha; zip_sha=$(sha256sum "$result" | cut -d' ' -f1)
    local direct_sha; direct_sha=$(sha256sum "$direct" | cut -d' ' -f1)
    if [ "$zip_sha" = "$direct_sha" ]; then
      ok "apply ZIP-wrapped patch"
    else
      bad "apply ZIP-wrapped patch" "SHA256 mismatch vs direct apply"
    fi
  else
    bad "apply ZIP-wrapped patch" "apply failed"
  fi

  # Info on ZIP-wrapped patch should work
  expect_ok "info ZIP-wrapped" "IPS" "$SLAP" info "$zipfile"

  # Explain on ZIP-wrapped patch should work
  expect_ok "explain ZIP-wrapped" "IPS" "$SLAP" explain "$zipfile"

  # ZIP with patch + chaff (readme) → extracts patch
  local chaffzip; chaffzip=$(mktmp).zip
  TMPFILES+=("$chaffzip")
  local readme; readme=$(mktmp).txt
  TMPFILES+=("$readme")
  echo "README" > "$readme"
  (cd "$(dirname "$patch")" && zip -j "$chaffzip" "$(basename "$patch")" "$readme") >/dev/null 2>&1
  expect_ok "ZIP with chaff filters readme" "IPS" "$SLAP" info "$chaffzip"

  # ZIP with 2 patches → ambiguous error
  local patch2="$REPO/test/data/dm4k/patch.bps"
  local multizip; multizip=$(mktmp).zip
  TMPFILES+=("$multizip")
  (cd "$(dirname "$patch")" && zip -j "$multizip" "$(basename "$patch")" "$(basename "$patch2")") >/dev/null 2>&1
  expect_fail "multi-entry ZIP fails" "candidate files" "$SLAP" info "$multizip"

  echo ""
}

############################################################################
# Convert with --with (apply-and-recreate path)
############################################################################

run_convert_with() {
  [[ -z "$FILTER" || "convert-with" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  local bps_patch="$REPO/test/data/dm4k/patch.bps"
  [ -f "$base" ] || { skp "convert-with" "base ROM not found"; return; }

  echo "--- convert with --with ---"

  # Bootstrap target for SHA256 reference
  local target; target=$(mktmp)
  cp "$base" "$target"
  "$SLAP" apply "$bps_patch" "$target" --in-place --no-backup >/dev/null 2>&1
  local target_sha; target_sha=$(sha256sum "$target" | cut -d' ' -f1)

  # BPS → IPS via --with
  for to_fmt in ips ips32 ups ppf3 pmsr; do
    local converted; converted=$(mktmp)
    local result; result=$(mktmp)
    if "$SLAP" convert "$bps_patch" --to "$to_fmt" -o "$converted" --with "$base" >/dev/null 2>&1; then
      cp "$base" "$result"
      if "$SLAP" apply "$converted" "$result" --in-place --no-backup --force >/dev/null 2>&1; then
        local got_sha; got_sha=$(sha256sum "$result" | cut -d' ' -f1)
        if [ "$got_sha" = "$target_sha" ]; then
          ok "convert BPS→$to_fmt via --with"
        else
          bad "convert BPS→$to_fmt via --with" "SHA256 mismatch"
        fi
      else
        bad "convert BPS→$to_fmt via --with" "apply of converted patch failed"
      fi
    else
      bad "convert BPS→$to_fmt via --with" "convert failed"
    fi
  done

  # IPS → BPS via --with (InPlace → InMemory direction)
  local ips_patch="$REPO/test/data/dm4k/patch.ips"
  local converted; converted=$(mktmp)
  local result; result=$(mktmp)
  if "$SLAP" convert "$ips_patch" --to bps -o "$converted" --with "$base" >/dev/null 2>&1; then
    cp "$base" "$result"
    if "$SLAP" apply "$converted" "$result" --in-place --no-backup --force >/dev/null 2>&1; then
      local got_sha; got_sha=$(sha256sum "$result" | cut -d' ' -f1)
      if [ "$got_sha" = "$target_sha" ]; then
        ok "convert IPS→BPS via --with"
      else
        bad "convert IPS→BPS via --with" "SHA256 mismatch"
      fi
    else
      bad "convert IPS→BPS via --with" "apply failed"
    fi
  else
    bad "convert IPS→BPS via --with" "convert failed"
  fi

  echo ""
}

############################################################################
# IPS truncation marker
############################################################################

run_ips_truncate() {
  [[ -z "$FILTER" || "truncate" == *"$FILTER"* ]] || return 0
  local base="$REPO/test/data/dm4k/base.gbc"
  [ -f "$base" ] || { skp "truncate" "base ROM not found"; return; }

  echo "--- IPS truncation marker ---"

  # Create a smaller modified file (truncated)
  local small; small=$(mktmp)
  dd if="$base" of="$small" bs=1 count=65536 2>/dev/null

  # Create IPS from base → truncated (should include truncation marker)
  local patch; patch=$(mktmp)
  if "$SLAP" create --format ips "$base" "$small" "$patch" >/dev/null 2>&1; then
    # Info should show truncation
    expect_ok "IPS truncation in info" "truncate" "$SLAP" info "$patch"

    # Apply should produce the truncated file
    local result; result=$(mktmp)
    cp "$base" "$result"
    if "$SLAP" apply "$patch" "$result" --in-place --no-backup --force >/dev/null 2>&1; then
      local small_sha; small_sha=$(sha256sum "$small" | cut -d' ' -f1)
      local result_sha; result_sha=$(sha256sum "$result" | cut -d' ' -f1)
      if [ "$result_sha" = "$small_sha" ]; then
        ok "IPS truncation apply correct"
      else
        bad "IPS truncation apply correct" "SHA256 mismatch"
      fi
    else
      bad "IPS truncation apply correct" "apply failed"
    fi
  else
    bad "IPS truncation" "create failed"
  fi

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
run_warnings
run_empty_diff
run_undo_output
run_archive
run_convert_with
run_ips_truncate

echo "passed: $pass  failed: $fail  skipped: $skip"
[ "$fail" -eq 0 ] || exit 1
