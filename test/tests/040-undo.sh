# 040-undo.sh — matrix-driven undo tests
# For each line in matrix/undo.txt: apply patch, undo, verify base SHA256.

_run_undo() {
  echo "--- undo tests ---"

  local undo_matrix="$REPO/test/matrix/undo.txt"
  [ -f "$undo_matrix" ] || { echo "SKIP  undo: matrix file not found"; return; }

  while IFS='|' read -r method base_rel patch_rel base_sha provenance; do
    method=$(trim "$method")
    base_rel=$(trim "$base_rel")
    patch_rel=$(trim "$patch_rel")
    base_sha=$(trim "$base_sha")

    local patch_name; patch_name=$(basename "$patch_rel")
    local test_name="undo/$method ($patch_name)"
    matches_filter "$test_name" || matches_filter "undo" || matches_filter "$method" || continue

    local base="$REPO/$base_rel"
    local patch="$REPO/$patch_rel"

    if [ ! -f "$base" ]; then
      skp "$test_name" "base ROM not found"
      continue
    fi
    if [ ! -f "$patch" ]; then
      skp "$test_name" "patch not found"
      continue
    fi

    local work; work=$(mktmp)
    cp "$base" "$work"

    if ! "$SLAP" apply "$patch" "$work" --in-place --no-backup --force >/dev/null 2>&1; then
      bad "$test_name" "apply failed"
      continue
    fi

    if ! "$SLAP" undo "$patch" "$work" >/dev/null 2>&1; then
      bad "$test_name" "undo failed"
      continue
    fi

    local got_sha; got_sha=$(sha "$work")
    if [ "$got_sha" = "$base_sha" ]; then
      ok "$test_name"
    else
      bad "$test_name" "SHA256 mismatch after undo"
    fi
  done < <(strip_comments "$undo_matrix")

  echo ""
}

_run_undo
