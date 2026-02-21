# 050-smoke.sh — info/explain smoke tests on all committed patches
# Auto-discovers all patch files in test/data/ and verifies info + explain
# don't crash (exit 0).

_run_smoke() {
  echo "--- smoke tests (info + explain) ---"

  local patchfile relpath

  for patchfile in "$REPO"/test/data/**/*.ips \
                   "$REPO"/test/data/**/*.ips32 \
                   "$REPO"/test/data/**/*.bps \
                   "$REPO"/test/data/**/*.ups \
                   "$REPO"/test/data/**/*.vcdiff \
                   "$REPO"/test/data/**/*.bsdiff \
                   "$REPO"/test/data/**/*.gdiff \
                   "$REPO"/test/data/**/*.xdelta1 \
                   "$REPO"/test/data/**/*.mod \
                   "$REPO"/test/data/**/*.ppf \
                   "$REPO"/test/data/**/*.ppf1.ppf \
                   "$REPO"/test/data/**/*.ppf2.ppf \
                   "$REPO"/test/data/**/*.ebp.ebp \
                   "$REPO"/test/data/**/*.rup.rup \
                   "$REPO"/test/data/**/*.aps.aps \
                   "$REPO"/test/data/**/*.aps \
                   "$REPO"/test/data/**/*.ninja1 \
                   "$REPO"/test/data/**/*.pchtxt; do
    [ -f "$patchfile" ] || continue
    relpath="${patchfile#$REPO/}"

    matches_filter "smoke/$relpath" || matches_filter "smoke" || continue

    if "$SLAP" info "$patchfile" >/dev/null 2>&1; then
      ok "info/$relpath"
    else
      bad "info/$relpath" "info crashed"
    fi

    if "$SLAP" explain "$patchfile" >/dev/null 2>&1; then
      ok "explain/$relpath"
    else
      bad "explain/$relpath" "explain crashed"
    fi
  done

  echo ""
}

_run_smoke
