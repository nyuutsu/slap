# 060-cli.sh — procedural CLI behavioral tests
# Covers error paths, flag combos, edge cases, warnings.
# Uses dm4k (4 MB) for speed.

DM4K_BASE="$REPO/test/data/dm4k/base.gbc"
DM4K_BPS="$REPO/test/data/dm4k/patch.bps"
DM4K_IPS="$REPO/test/data/dm4k/patch.ips"
DM4K_UPS="$REPO/test/data/dm4k/patch.ups"

############################################################################
# Corrupt / invalid input
############################################################################

run_corrupt() {
  matches_filter "corrupt" || return 0
  echo "--- corrupt / invalid input ---"

  local empty; empty=$(mktmp)
  : > "$empty"
  expect_fail "corrupt/info empty file" "unknown" "$SLAP" info "$empty"
  expect_fail "corrupt/explain empty file" "unknown" "$SLAP" explain "$empty"

  local garbage; garbage=$(mktmp)
  dd if=/dev/urandom of="$garbage" bs=256 count=1 2>/dev/null
  expect_fail "corrupt/info random garbage" "unknown" "$SLAP" info "$garbage"

  local trunc; trunc=$(mktmp)
  printf 'PATCH\x01\x02' > "$trunc"
  expect_ok "corrupt/info truncated IPS (graceful)" "0" "$SLAP" info "$trunc"

  local trunc_bps; trunc_bps=$(mktmp)
  printf 'BPS1' > "$trunc_bps"
  expect_fail "corrupt/info truncated BPS" "" "$SLAP" info "$trunc_bps"

  echo ""
}

############################################################################
# --dry-run
############################################################################

run_dryrun() {
  matches_filter "dryrun" || matches_filter "dry-run" || return 0
  [ -f "$DM4K_BASE" ] || { skp "dryrun" "base ROM not found"; return; }
  echo "--- --dry-run ---"

  local out; out=$(mktmp)
  rm -f "$out"
  expect_ok "dryrun/reports action" "would apply" \
    "$SLAP" apply "$DM4K_BPS" "$DM4K_BASE" -o "$out" --dry-run
  if [ -f "$out" ]; then
    bad "dryrun/no output file" "output file was created"
  else
    ok "dryrun/no output file"
  fi

  expect_ok "dryrun/shows CRC" "source CRC" \
    "$SLAP" apply "$DM4K_BPS" "$DM4K_BASE" --dry-run

  local work; work=$(mktmp)
  cp "$DM4K_BASE" "$work"
  local before_sha; before_sha=$(sha "$work")
  "$SLAP" apply "$DM4K_BPS" "$work" --in-place --no-backup --dry-run >/dev/null 2>&1 || true
  local after_sha; after_sha=$(sha "$work")
  if [ "$before_sha" = "$after_sha" ]; then
    ok "dryrun/in-place leaves source untouched"
  else
    bad "dryrun/in-place leaves source untouched" "source was modified"
  fi

  echo ""
}

############################################################################
# --force (CRC mismatch override)
############################################################################

run_force() {
  matches_filter "force" || return 0
  [ -f "$DM4K_BASE" ] || { skp "force" "base ROM not found"; return; }
  echo "--- --force (CRC mismatch) ---"

  local wrong; wrong=$(mktmp)
  dd if=/dev/urandom of="$wrong" bs=4096 count=1024 2>/dev/null
  local crc_out; crc_out=$(mktmp)
  rm -f "$crc_out"
  expect_fail "force/UPS wrong source fails" "CRC mismatch" \
    "$SLAP" apply "$DM4K_UPS" "$wrong" -o "$crc_out"

  local out; out=$(mktmp)
  rm -f "$out"
  expect_ok "force/UPS wrong source + --force" "applied" \
    "$SLAP" apply "$DM4K_UPS" "$wrong" -o "$out" --force

  echo ""
}

############################################################################
# --in-place + --no-backup
############################################################################

run_inplace() {
  matches_filter "inplace" || return 0
  [ -f "$DM4K_BASE" ] || { skp "inplace" "base ROM not found"; return; }
  echo "--- --in-place flag combinations ---"

  local work; work=$(mktmp)
  cp "$DM4K_BASE" "$work"
  "$SLAP" apply "$DM4K_IPS" "$work" --in-place >/dev/null 2>&1
  if [ -f "${work}.bak" ]; then
    ok "inplace/creates .bak"
    rm -f "${work}.bak"
  else
    bad "inplace/creates .bak" "no .bak created"
  fi

  cp "$DM4K_BASE" "$work"
  "$SLAP" apply "$DM4K_IPS" "$work" --in-place --no-backup >/dev/null 2>&1
  if [ -f "${work}.bak" ]; then
    bad "inplace/--no-backup skips .bak" ".bak was created"
    rm -f "${work}.bak"
  else
    ok "inplace/--no-backup skips .bak"
  fi

  echo ""
}

############################################################################
# Output file collision
############################################################################

run_collision() {
  matches_filter "collision" || return 0
  [ -f "$DM4K_BASE" ] || { skp "collision" "base ROM not found"; return; }
  echo "--- output collision ---"

  local out; out=$(mktmp)
  echo "existing" > "$out"
  expect_fail "collision/overwrite refused" "already exists" \
    "$SLAP" apply "$DM4K_IPS" "$DM4K_BASE" -o "$out"

  expect_ok "collision/overwrite with --force" "applied" \
    "$SLAP" apply "$DM4K_IPS" "$DM4K_BASE" -o "$out" --force

  echo ""
}

############################################################################
# --verbose
############################################################################

run_verbose() {
  matches_filter "verbose" || return 0
  [ -f "$DM4K_BASE" ] || { skp "verbose" "base ROM not found"; return; }
  echo "--- --verbose ---"

  local out; out=$(mktmp)
  expect_ok "verbose/prints records" "\\[1/" \
    "$SLAP" apply "$DM4K_IPS" "$DM4K_BASE" -o "$out" --verbose --force

  echo ""
}

############################################################################
# Undo error paths
############################################################################

run_undo_errors() {
  matches_filter "undo" || return 0
  [ -f "$DM4K_BASE" ] || { skp "undo" "base ROM not found"; return; }
  echo "--- undo error paths ---"

  expect_fail "undo/unsupported IPS" "undo not supported" \
    "$SLAP" undo "$DM4K_IPS" "$DM4K_BASE"

  expect_fail "undo/unsupported BPS" "undo not supported" \
    "$SLAP" undo "$DM4K_BPS" "$DM4K_BASE"

  echo ""
}

############################################################################
# Compound flag combinations
############################################################################

run_compound() {
  matches_filter "compound" || return 0
  [ -f "$DM4K_BASE" ] || { skp "compound" "base ROM not found"; return; }
  echo "--- compound flag combinations ---"

  local work; work=$(mktmp)
  cp "$DM4K_BASE" "$work"
  expect_ok "compound/in-place+force+verbose+no-backup (IPS)" "applied" \
    "$SLAP" apply "$DM4K_IPS" "$work" --in-place --force --verbose --no-backup

  cp "$DM4K_BASE" "$work"
  expect_ok "compound/in-place+force+verbose+no-backup (BPS)" "applied" \
    "$SLAP" apply "$DM4K_BPS" "$work" --in-place --force --verbose --no-backup

  local out
  out=$("$SLAP" apply "$DM4K_IPS" "$DM4K_BASE" --dry-run --verbose 2>&1) || true
  if echo "$out" | grep -q "would apply" && echo "$out" | grep -qE "\[1/"; then
    ok "compound/dry-run+verbose shows both"
  else
    bad "compound/dry-run+verbose shows both" "missing expected output"
  fi

  work=$(mktmp)
  cp "$DM4K_BASE" "$work"
  local before_sha; before_sha=$(sha "$work")
  "$SLAP" apply "$DM4K_BPS" "$work" --in-place --dry-run --force >/dev/null 2>&1 || true
  local after_sha; after_sha=$(sha "$work")
  if [ "$before_sha" = "$after_sha" ]; then
    ok "compound/dry-run+force doesn't modify"
  else
    bad "compound/dry-run+force doesn't modify" "source was modified"
  fi

  local explicit; explicit=$(mktmp)
  rm -f "$explicit"
  expect_ok "compound/explicit -o output" "applied" \
    "$SLAP" apply "$DM4K_IPS" "$DM4K_BASE" -o "$explicit"
  if [ -f "$explicit" ]; then
    ok "compound/explicit -o file created"
  else
    bad "compound/explicit -o file created" "file not found"
  fi

  echo ""
}

############################################################################
# Create flags (PPF3 --undo --validate)
############################################################################

run_create_flags() {
  matches_filter "create" || return 0
  [ -f "$DM4K_BASE" ] || { skp "create" "base ROM not found"; return; }
  echo "--- create flag combinations ---"

  local target; target=$(mktmp)
  cp "$DM4K_BASE" "$target"
  "$SLAP" apply "$DM4K_BPS" "$target" --in-place --no-backup >/dev/null 2>&1

  local patch; patch=$(mktmp)
  expect_ok "create/ppf3+undo+validate+desc" "wrote" \
    "$SLAP" create --format ppf3 --undo --validate -d "test patch" "$DM4K_BASE" "$target" "$patch"

  expect_ok "create/ppf3 undo data present" "undo" \
    "$SLAP" info "$patch"

  echo ""
}

############################################################################
# Hidden aliases
############################################################################

run_aliases() {
  matches_filter "aliases" || return 0
  [ -f "$DM4K_BASE" ] || { skp "aliases" "base ROM not found"; return; }
  echo "--- hidden aliases ---"

  local out; out=$(mktmp)
  expect_ok "aliases/--yolo" "applied" \
    "$SLAP" apply "$DM4K_IPS" "$DM4K_BASE" -o "$out" --yolo

  expect_ok "aliases/--send-it" "applied" \
    "$SLAP" apply "$DM4K_IPS" "$DM4K_BASE" -o "$out" --send-it

  local work; work=$(mktmp)
  cp "$DM4K_BASE" "$work"
  expect_ok "aliases/--clobber" "applied" \
    "$SLAP" apply "$DM4K_IPS" "$work" --clobber --no-backup

  echo ""
}

############################################################################
# Patch health warnings
############################################################################

run_warnings() {
  matches_filter "warnings" || return 0
  echo "--- patch health warnings ---"

  local trunc; trunc=$(mktmp)
  printf 'PATCH\x01\x02' > "$trunc"
  expect_ok "warnings/truncated IPS no EOF" "no EOF marker" "$SLAP" info "$trunc"
  expect_ok "warnings/truncated IPS empty" "empty patch" "$SLAP" info "$trunc"

  printf 'PATCHEOF' > "$trunc"
  local out
  out=$("$SLAP" info "$trunc" 2>&1)
  if echo "$out" | grep -q "empty patch" && ! echo "$out" | grep -q "no EOF"; then
    ok "warnings/empty IPS warns empty only"
  else
    bad "warnings/empty IPS warns empty only" "unexpected warning pattern: $out"
  fi

  out=$("$SLAP" info "$REPO/test/data/dm4k/patch.ips" 2>&1)
  if echo "$out" | grep -q "warning"; then
    bad "warnings/normal IPS no warnings" "unexpected warning: $out"
  else
    ok "warnings/normal IPS no warnings"
  fi

  echo ""
}

############################################################################
# Empty diff (identical files)
############################################################################

run_empty_diff() {
  matches_filter "empty" || return 0
  [ -f "$DM4K_BASE" ] || { skp "empty-diff" "base ROM not found"; return; }
  echo "--- empty diff (identical files) ---"

  for fmt in bps ips ips32 ups ppf3 pmsr; do
    local patch; patch=$(mktmp)
    if "$SLAP" create --format "$fmt" "$DM4K_BASE" "$DM4K_BASE" "$patch" >/dev/null 2>&1; then
      local result; result=$(mktmp)
      cp "$DM4K_BASE" "$result"
      if "$SLAP" apply "$patch" "$result" --in-place --no-backup --force >/dev/null 2>&1; then
        local base_sha; base_sha=$(sha "$DM4K_BASE")
        local result_sha; result_sha=$(sha "$result")
        if [ "$base_sha" = "$result_sha" ]; then
          ok "empty-diff/$fmt"
        else
          bad "empty-diff/$fmt" "SHA256 mismatch"
        fi
      else
        bad "empty-diff/$fmt" "apply of empty patch failed"
      fi
    else
      bad "empty-diff/$fmt" "create from identical files failed"
    fi
  done

  echo ""
}

############################################################################
# Undo with -o (output redirect)
############################################################################

run_undo_output() {
  matches_filter "undo-output" || return 0
  [ -f "$DM4K_BASE" ] || { skp "undo-output" "base ROM not found"; return; }
  echo "--- undo with -o output ---"

  local work; work=$(mktmp)
  local out; out=$(mktmp)
  cp "$DM4K_BASE" "$work"
  "$SLAP" apply "$DM4K_UPS" "$work" --in-place --no-backup --force >/dev/null 2>&1
  local patched_sha; patched_sha=$(sha "$work")

  rm -f "$out"
  "$SLAP" undo "$DM4K_UPS" "$work" -o "$out" >/dev/null 2>&1
  local base_sha; base_sha=$(sha "$DM4K_BASE")
  local out_sha; out_sha=$(sha "$out")
  local work_sha; work_sha=$(sha "$work")

  if [ "$out_sha" = "$base_sha" ]; then
    ok "undo-output/produces original"
  else
    bad "undo-output/produces original" "SHA256 mismatch"
  fi

  if [ "$work_sha" = "$patched_sha" ]; then
    ok "undo-output/leaves source untouched"
  else
    bad "undo-output/leaves source untouched" "source was modified"
  fi

  echo ""
}

############################################################################
# Archive unwrapping
############################################################################

run_archive() {
  matches_filter "archive" || return 0
  [ -f "$DM4K_BASE" ] || { skp "archive" "base ROM not found"; return; }
  command -v zip >/dev/null || { skp "archive" "zip not found"; return; }
  command -v unzip >/dev/null || { skp "archive" "unzip not found"; return; }
  echo "--- archive unwrapping ---"

  local zipfile; zipfile=$(mktmp).zip
  (cd "$(dirname "$DM4K_IPS")" && zip -j "$zipfile" "$(basename "$DM4K_IPS")") >/dev/null 2>&1

  local result; result=$(mktmp)
  cp "$DM4K_BASE" "$result"
  if "$SLAP" apply "$zipfile" "$result" --in-place --no-backup >/dev/null 2>&1; then
    local direct; direct=$(mktmp)
    cp "$DM4K_BASE" "$direct"
    "$SLAP" apply "$DM4K_IPS" "$direct" --in-place --no-backup >/dev/null 2>&1
    local zip_sha; zip_sha=$(sha "$result")
    local direct_sha; direct_sha=$(sha "$direct")
    if [ "$zip_sha" = "$direct_sha" ]; then
      ok "archive/apply ZIP-wrapped patch"
    else
      bad "archive/apply ZIP-wrapped patch" "SHA256 mismatch"
    fi
  else
    bad "archive/apply ZIP-wrapped patch" "apply failed"
  fi

  expect_ok "archive/info ZIP-wrapped" "IPS" "$SLAP" info "$zipfile"
  expect_ok "archive/explain ZIP-wrapped" "IPS" "$SLAP" explain "$zipfile"

  local chaffzip; chaffzip=$(mktmp).zip
  local readme; readme=$(mktmp).txt
  echo "README" > "$readme"
  (cd "$(dirname "$DM4K_IPS")" && zip -j "$chaffzip" "$(basename "$DM4K_IPS")" "$readme") >/dev/null 2>&1
  expect_ok "archive/ZIP chaff filters readme" "IPS" "$SLAP" info "$chaffzip"

  local multizip; multizip=$(mktmp).zip
  (cd "$(dirname "$DM4K_IPS")" && zip -j "$multizip" "$(basename "$DM4K_IPS")" "$(basename "$DM4K_BPS")") >/dev/null 2>&1
  expect_fail "archive/multi-entry ZIP fails" "candidate files" "$SLAP" info "$multizip"

  echo ""
}

############################################################################
# IPS truncation marker
############################################################################

run_ips_truncate() {
  matches_filter "truncate" || return 0
  [ -f "$DM4K_BASE" ] || { skp "truncate" "base ROM not found"; return; }
  echo "--- IPS truncation marker ---"

  local small; small=$(mktmp)
  dd if="$DM4K_BASE" of="$small" bs=1 count=65536 2>/dev/null

  local patch; patch=$(mktmp)
  if "$SLAP" create --format ips "$DM4K_BASE" "$small" "$patch" >/dev/null 2>&1; then
    expect_ok "truncate/IPS truncation in info" "truncate" "$SLAP" info "$patch"

    local result; result=$(mktmp)
    cp "$DM4K_BASE" "$result"
    if "$SLAP" apply "$patch" "$result" --in-place --no-backup --force >/dev/null 2>&1; then
      local small_sha; small_sha=$(sha "$small")
      local result_sha; result_sha=$(sha "$result")
      if [ "$result_sha" = "$small_sha" ]; then
        ok "truncate/IPS truncation apply correct"
      else
        bad "truncate/IPS truncation apply correct" "SHA256 mismatch"
      fi
    else
      bad "truncate/IPS truncation apply correct" "apply failed"
    fi
  else
    bad "truncate/IPS truncation" "create failed"
  fi

  echo ""
}

############################################################################
# VCDIFF custom code table
############################################################################

run_custom_codetable() {
  matches_filter "custom-codetable" || return 0
  echo "--- VCDIFF custom code table ---"

  local patch; patch=$(mktmp)
  printf '\xd6\xc3\xc4\x00\x02\x16\x05\x02' > "$patch"
  printf '\xd6\xc3\xc4\x00\x00\x01\x8c\x00\x00\x0a' >> "$patch"
  printf '\x8c\x00\x00\x00\x03\x01\x13\x8c\x00\x00' >> "$patch"
  printf '\x01\x08\x00\x0a\x0a\x00\x02\x02\x01\x45\x45\x18\x03\x00' >> "$patch"

  local source; source=$(mktmp)
  printf 'AABBCCDD' > "$source"

  expect_ok "custom-codetable/info" "custom .near=5, same=2." "$SLAP" info "$patch"

  local result; result=$(mktmp)
  if "$SLAP" apply "$patch" "$source" -o "$result" --force 2>/dev/null; then
    local got
    got=$(cat "$result")
    if [ "$got" = "AABBCCDDEE" ]; then
      ok "custom-codetable/apply"
    else
      bad "custom-codetable/apply" "expected 'AABBCCDDEE', got '$got'"
    fi
  else
    bad "custom-codetable/apply" "apply failed"
  fi

  echo ""
}

############################################################################
# Run all CLI tests
############################################################################

run_corrupt
run_dryrun
run_force
run_inplace
run_collision
run_verbose
run_undo_errors
run_compound
run_create_flags
run_aliases
run_warnings
run_empty_diff
run_undo_output
run_archive
run_ips_truncate
run_custom_codetable
