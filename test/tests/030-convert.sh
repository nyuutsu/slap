# 030-convert.sh — spec-driven conversion tests
# Parses specs/convert.txt and runs accept/reject/warning checks.

_run_convert() {
  echo "--- conversion specs ---"

  local convert_spec="$REPO/test/specs/convert.txt"
  [ -f "$convert_spec" ] || { echo "SKIP  convert: spec file not found"; return; }

  while IFS='|' read -r src_fmt tgt_fmt patch_rel base_rel target_sha result expected_warnings flags; do
    src_fmt=$(trim "$src_fmt")
    tgt_fmt=$(trim "$tgt_fmt")
    patch_rel=$(trim "$patch_rel")
    base_rel=$(trim "$base_rel")
    target_sha=$(trim "$target_sha")
    result=$(trim "$result")
    expected_warnings=$(trim "$expected_warnings")
    flags=$(trim "$flags")

    local test_name="convert/$src_fmt→$tgt_fmt"
    matches_filter "$test_name" || matches_filter "convert" || matches_filter "$src_fmt" || matches_filter "$tgt_fmt" || continue

    local patch="$REPO/$patch_rel"
    if [ ! -f "$patch" ]; then
      skp "$test_name" "patch not found: $patch_rel"
      continue
    fi

    # --- skip known bugs ---
    if [[ "$result" == skip:* ]]; then
      skp "$test_name" "${result#skip:}"
      continue
    fi

    # --- reject tests ---
    if [[ "$result" == reject:* ]]; then
      local pattern="${result#reject:}"
      local convert_args=("$patch" "--to" "$tgt_fmt")
      if [[ "$flags" == *"--with"* ]] && [ -n "$base_rel" ]; then
        convert_args+=("--with" "$REPO/$base_rel")
        local extra_flags=""
        local f
        for f in $flags; do
          [ "$f" = "--with" ] && continue
          extra_flags+=" $f"
        done
        flags=$(trim "$extra_flags")
      fi
      if [ -n "$flags" ]; then
        local f
        for f in $flags; do convert_args+=("$f"); done
      fi
      expect_fail "$test_name" "$pattern" "$SLAP" convert "${convert_args[@]}"
      continue
    fi

    # --- accept tests ---
    if [ "$result" != "accept" ]; then
      bad "$test_name" "unknown result type: $result"
      continue
    fi

    local base=""
    [ -n "$base_rel" ] && base="$REPO/$base_rel"

    if [ -n "$base" ] && [ ! -f "$base" ]; then
      skp "$test_name" "base ROM not found: $base_rel"
      continue
    fi

    local conv; conv=$(mktmp)
    local convert_args=("$patch" "--to" "$tgt_fmt" "-o" "$conv")
    # Handle --with flag: pass base as --with argument
    if [[ "$flags" == *"--with"* ]]; then
      convert_args+=("--with" "$base")
      local extra_flags=""
      local f
      for f in $flags; do
        [ "$f" = "--with" ] && continue
        extra_flags+=" $f"
      done
      flags=$(trim "$extra_flags")
    fi
    if [ -n "$flags" ]; then
      local f
      for f in $flags; do convert_args+=("$f"); done
    fi

    local convert_out
    if ! convert_out=$("$SLAP" convert "${convert_args[@]}" 2>&1); then
      bad "$test_name" "convert failed: $convert_out"
      continue
    fi

    # Check warnings (comma-separated patterns, each must match some line)
    if [ -n "$expected_warnings" ]; then
      local warn_ok=true
      local wp
      local -a _warn_pats
      IFS=',' read -ra _warn_pats <<< "$expected_warnings"
      for wp in "${_warn_pats[@]}"; do
        wp=$(trim "$wp")
        if ! echo "$convert_out" | grep -qiE "$wp"; then
          bad "$test_name" "expected warning '$wp' not found in: $convert_out"
          warn_ok=false
          break
        fi
      done
      [ "$warn_ok" = true ] || continue
    fi

    # Apply converted patch and verify SHA256
    if [ -n "$base" ] && [ -n "$target_sha" ]; then
      local apply_result; apply_result=$(mktmp)
      cp "$base" "$apply_result"
      if ! "$SLAP" apply "$conv" "$apply_result" --in-place --no-backup --force >/dev/null 2>&1; then
        bad "$test_name" "apply of converted patch failed"
        continue
      fi

      local got_sha; got_sha=$(sha "$apply_result")
      if [ "$got_sha" = "$target_sha" ]; then
        ok "$test_name"
      else
        bad "$test_name" "SHA256 mismatch (got $got_sha)"
      fi
    else
      ok "$test_name"
    fi
    test_cleanup
  done < <(strip_comments "$convert_spec")

  echo ""
}

_run_convert
