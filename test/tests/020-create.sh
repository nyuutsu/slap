# 020-create.sh — spec-driven create round-trip tests
# For each line in specs/create.txt: bootstrap target, create patch, apply, verify SHA256.

_run_create() {
  echo "--- create round-trips ---"

  declare -A BOOTSTRAP_CACHE

  local create_spec="$REPO/test/specs/create.txt"
  [ -f "$create_spec" ] || { echo "SKIP  create: spec file not found"; return; }

  while IFS='|' read -r fmt scenario base_rel bootstrap_rel target_sha provenance; do
    fmt=$(trim "$fmt")
    scenario=$(trim "$scenario")
    base_rel=$(trim "$base_rel")
    bootstrap_rel=$(trim "$bootstrap_rel")
    target_sha=$(trim "$target_sha")

    local test_name="create/$fmt ($scenario)"
    matches_filter "$test_name" || matches_filter "$scenario" || matches_filter "$fmt" || continue

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
      if ! verify_sha "create/$scenario bootstrap" "$target_file" "$target_sha"; then
        bad "$test_name" "bootstrap SHA256 checkpoint failed"
        continue
      fi
      BOOTSTRAP_CACHE[$cache_key]="$target_file"
    fi
    local target="${BOOTSTRAP_CACHE[$cache_key]}"

    local patch; patch=$(mktmp)
    if ! "$SLAP" create --format "$fmt" "$base" "$target" "$patch" >/dev/null 2>&1; then
      bad "$test_name" "create failed"
      continue
    fi

    local result; result=$(mktmp)
    cp "$base" "$result"
    if ! "$SLAP" apply "$patch" "$result" --in-place --no-backup --force >/dev/null 2>&1; then
      bad "$test_name" "apply of created patch failed"
      continue
    fi

    local got_sha; got_sha=$(sha "$result")
    if [ "$got_sha" = "$target_sha" ]; then
      ok "$test_name"
    else
      bad "$test_name" "SHA256 mismatch"
    fi
    test_cleanup
  done < <(strip_comments "$create_spec")

  for _k in "${!BOOTSTRAP_CACHE[@]}"; do
    rm -f "${BOOTSTRAP_CACHE[$_k]}"
  done
  unset BOOTSTRAP_CACHE
  echo ""
}

_run_create
