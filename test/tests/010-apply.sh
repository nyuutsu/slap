# 010-apply.sh — suite-driven apply tests
# Discovers .suite manifests and verifies all patches produce correct output.

SUITE_DIR="$REPO/test/suites"

run_suite() {
  local suite_file="$1"
  local suite_name
  suite_name=$(basename "$suite_file" .suite)

  local base="" sha256="" desc=""

  # Parse header
  while IFS= read -r line; do
    line="${line%%#*}"
    [[ -z "${line// /}" ]] && continue
    case "$line" in
      base:*)   base=$(trim "${line#base:}") ;;
      sha256:*) sha256=$(trim "${line#sha256:}") ;;
      desc:*)   desc=$(trim "${line#desc:}") ;;
      *"|"*)    break ;;
    esac
  done < "$suite_file"

  if [ -z "$base" ] || [ -z "$sha256" ]; then
    skp "apply/$suite_name" "missing base or sha256 in manifest"
    return
  fi

  local base_path="$REPO/$base"
  if [ ! -f "$base_path" ]; then
    skp "apply/$suite_name" "base ROM not found: $base"
    return
  fi

  echo "--- $desc ---"

  while IFS= read -r line; do
    line="${line%%#*}"
    [[ -z "${line// /}" ]] && continue
    case "$line" in
      base:*|sha256:*|desc:*) continue ;;
    esac

    IFS='|' read -r fmt path confidence provenance <<< "$line"
    fmt=$(trim "$fmt")
    path=$(trim "$path")
    confidence=$(trim "$confidence")
    provenance=$(trim "$provenance")

    local test_name="apply/$suite_name/$fmt"
    matches_filter "$test_name" || matches_filter "$suite_name" || matches_filter "$fmt" || continue

    local patch_path="$REPO/$path"

    if [ "$confidence" = "broken" ]; then
      skp "$test_name" "broken ($provenance)"
      continue
    fi

    if [ "$confidence" = "untested" ] && [ ! -f "$patch_path" ]; then
      skp "$test_name" "untested, file missing"
      continue
    fi

    if [ ! -f "$patch_path" ]; then
      skp "$test_name" "patch not found: $path"
      continue
    fi

    local tmp; tmp=$(mktmp)
    cp "$base_path" "$tmp"
    if "$SLAP" apply "$patch_path" "$tmp" --in-place --no-backup >/dev/null 2>&1; then
      local got_sha; got_sha=$(sha "$tmp")
      if [ "$got_sha" = "$sha256" ]; then
        ok "$test_name"
      else
        bad "$test_name" "SHA256 mismatch"
      fi
    else
      bad "$test_name" "slap apply returned error"
    fi
  done < "$suite_file"
  echo ""
}

for suite in "$SUITE_DIR"/*.suite; do
  [ -f "$suite" ] || continue
  run_suite "$suite"
done
