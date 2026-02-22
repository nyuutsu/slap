# 025-crossval.sh — cross-validation: slap create → external tool apply → SHA256
# Tests that patches created by slap are valid by applying them with
# independent external tools and verifying the output matches.

_run_crossval() {
  echo "--- cross-validation ---"

  local FLIPS="${FLIPS:-$HOME/repos/Flips/flips}"
  local BSPATCH="${BSPATCH:-/usr/bin/bspatch}"
  local XDELTA3="${XDELTA3:-/usr/bin/xdelta3}"
  local ROMPATCHER="${ROMPATCHER:-$HOME/repos/RomPatcher[dot]js/index.js}"

  declare -A BOOTSTRAP_CACHE

  local crossval_spec="$REPO/test/specs/crossval.txt"
  [ -f "$crossval_spec" ] || { echo "SKIP  crossval: spec file not found"; return; }

  while IFS='|' read -r fmt scenario base_rel bootstrap_rel target_sha tool; do
    fmt=$(trim "$fmt")
    scenario=$(trim "$scenario")
    base_rel=$(trim "$base_rel")
    bootstrap_rel=$(trim "$bootstrap_rel")
    target_sha=$(trim "$target_sha")
    tool=$(trim "$tool")

    local test_name="crossval/$fmt ($scenario)"
    matches_filter "$test_name" || matches_filter "$scenario" || matches_filter "$fmt" || matches_filter "crossval" || continue

    # Check external tool availability
    local tool_path=""
    case "$tool" in
      flips)       tool_path="$FLIPS" ;;
      bspatch)     tool_path="$BSPATCH" ;;
      xdelta3)     tool_path="$XDELTA3" ;;
      rompatcher)  tool_path="$ROMPATCHER" ;;
      *)           bad "$test_name" "unknown tool: $tool"; continue ;;
    esac
    if [ "$tool" = "rompatcher" ]; then
      if ! command -v node >/dev/null 2>&1 || [ ! -f "$tool_path" ]; then
        skp "$test_name" "rompatcher not found"
        continue
      fi
    elif [ ! -x "$tool_path" ]; then
      skp "$test_name" "$tool not found"
      continue
    fi

    local base="$REPO/$base_rel"
    local bootstrap_patch="$REPO/$bootstrap_rel"

    if [ ! -f "$base" ]; then
      skp "$test_name" "base ROM not found"
      continue
    fi
    if [ ! -f "$bootstrap_patch" ]; then
      skp "$test_name" "bootstrap patch not found"
      continue
    fi

    # Bootstrap target (cached)
    local cache_key="${base_rel}|${bootstrap_rel}"
    if [ -z "${BOOTSTRAP_CACHE[$cache_key]+x}" ]; then
      local target_file; target_file=$(bootstrap "$base" "$bootstrap_patch")
      if ! verify_sha "crossval/$scenario bootstrap" "$target_file" "$target_sha"; then
        bad "$test_name" "bootstrap SHA256 checkpoint failed"
        continue
      fi
      BOOTSTRAP_CACHE[$cache_key]="$target_file"
    fi
    local target="${BOOTSTRAP_CACHE[$cache_key]}"

    # Create patch with slap
    local patch; patch=$(mktmp)
    if ! "$SLAP" create --format "$fmt" "$base" "$target" "$patch" >/dev/null 2>&1; then
      bad "$test_name" "slap create failed"
      continue
    fi

    # Apply with external tool
    local result; result=$(mktmp)
    local apply_ok=true
    case "$tool" in
      flips)
        if ! "$tool_path" --apply "$patch" "$base" "$result" >/dev/null 2>&1; then
          bad "$test_name" "flips --apply failed"
          apply_ok=false
        fi
        ;;
      bspatch)
        if ! "$tool_path" "$base" "$result" "$patch" >/dev/null 2>&1; then
          bad "$test_name" "bspatch failed"
          apply_ok=false
        fi
        ;;
      xdelta3)
        if ! "$tool_path" -d -s "$base" "$patch" "$result" >/dev/null 2>&1; then
          bad "$test_name" "xdelta3 -d failed"
          apply_ok=false
        fi
        ;;
      rompatcher)
        # RPJS writes "<stem> (patched).<ext>" to CWD — run from a tmp dir
        local rpdir; rpdir=$(mktemp -d -p "$TMPDIR_BASE")
        local base_name; base_name=$(basename "$base")
        local stem="${base_name%.*}"
        local ext="${base_name##*.}"
        cp "$base" "$rpdir/$base_name"
        if ! (cd "$rpdir" && node "$tool_path" patch "$base_name" "$patch") >/dev/null 2>&1; then
          bad "$test_name" "rompatcher failed"
          apply_ok=false
        elif [ -f "$rpdir/${stem} (patched).${ext}" ]; then
          cp "$rpdir/${stem} (patched).${ext}" "$result"
        else
          bad "$test_name" "rompatcher output not found"
          apply_ok=false
        fi
        ;;
    esac
    [ "$apply_ok" = true ] || continue

    # Verify SHA256
    local got_sha; got_sha=$(sha "$result")
    if [ "$got_sha" = "$target_sha" ]; then
      ok "$test_name"
    else
      bad "$test_name" "SHA256 mismatch (got $got_sha)"
    fi
    test_cleanup
  done < <(strip_comments "$crossval_spec")

  for _k in "${!BOOTSTRAP_CACHE[@]}"; do
    rm -f "${BOOTSTRAP_CACHE[$_k]}"
  done
  unset BOOTSTRAP_CACHE
  echo ""
}

_run_crossval
