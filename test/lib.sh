#!/usr/bin/env bash
# slap test library — shared helpers for all test modules
# Sourced by run.sh; not meant to be run standalone.

pass=0
fail=0
skip=0

TMPDIR_BASE=$(mktemp -d -p "${SLAP_TMPDIR:-${TMPDIR:-/tmp}}" slap-test.XXXXXX)
trap 'rm -rf "$TMPDIR_BASE"' EXIT

# Per-test temp file tracking.  mktmp registers files; test_cleanup
# removes them immediately.  Every test iteration calls test_cleanup
# when done so nothing accumulates.  No EXIT trap — if the process
# is killed, at most one iteration's files remain (a few hundred MB),
# not the entire suite's worth.
_tmpfiles=()

mktmp() {
  local f
  f=$(mktemp -p "$TMPDIR_BASE")
  _tmpfiles+=("$f")
  echo "$f"
}

mktmp_ext() {
  local base
  base=$(mktemp -p "$TMPDIR_BASE")
  rm -f "$base"
  _tmpfiles+=("${base}.$1")
  echo "${base}.$1"
}

test_cleanup() {
  local f
  for f in "${_tmpfiles[@]}"; do
    rm -f "$f"
  done
  _tmpfiles=()
}

# final_cleanup — call at the end of run.sh to remove TMPDIR_BASE.
final_cleanup() {
  rm -rf "$TMPDIR_BASE"
}

sha() { sha256sum "$1" | cut -d' ' -f1; }

ok() {
  echo "OK    $1"
  ((pass++)) || true
}

bad() {
  echo "FAIL  $1 — $2"
  ((fail++)) || true
}

skp() {
  echo "SKIP  $1 — $2"
  ((skip++)) || true
}

# matches_filter <label>
# Returns 0 (true) if the label matches $FILTER or no filter is set.
matches_filter() {
  [[ -z "$FILTER" ]] && return 0
  [[ "$1" == *"$FILTER"* ]] && return 0
  return 1
}

# expect_fail <label> <pattern> <cmd...>
# Expects nonzero exit; stderr+stdout must match pattern (case-insensitive).
expect_fail() {
  local name="$1" pattern="$2"
  shift 2
  local out
  if out=$("$@" 2>&1); then
    bad "$name" "expected failure but got success"
    return
  fi
  if echo "$out" | grep -qiE "$pattern"; then
    ok "$name"
  else
    bad "$name" "expected '$pattern' in output, got: $out"
  fi
}

# expect_ok <label> <pattern> <cmd...>
# Expects zero exit; stdout+stderr must match pattern (case-insensitive).
expect_ok() {
  local name="$1" pattern="$2"
  shift 2
  local out
  if ! out=$("$@" 2>&1); then
    bad "$name" "expected success but got failure: $out"
    return
  fi
  if echo "$out" | grep -qiE "$pattern"; then
    ok "$name"
  else
    bad "$name" "expected '$pattern' in output, got: $out"
  fi
}

# bootstrap <base> <patch> → prints tmp path to patched file
# Fatal on failure.  Caller is responsible for rm when done.
bootstrap() {
  local base="$1" patch="$2"
  local target; target=$(mktemp -p "$TMPDIR_BASE")
  cp "$base" "$target"
  if ! "$SLAP" apply "$patch" "$target" --in-place --no-backup --force >/dev/null 2>&1; then
    echo "FATAL: bootstrap apply failed: $SLAP apply $patch"
    exit 1
  fi
  echo "$target"
}

# verify_sha <label> <file> <expected_sha>
# Checks SHA256 match.
verify_sha() {
  local label="$1" file="$2" expected="$3"
  local got; got=$(sha "$file")
  if [ "$got" = "$expected" ]; then
    return 0
  else
    echo "FATAL: SHA256 checkpoint failed for $label"
    echo "  expected: $expected"
    echo "  got:      $got"
    return 1
  fi
}

# strip_comments <file>
# Reads a spec file, strips comments and blank lines.
strip_comments() {
  grep -v '^\s*#' "$1" | grep -v '^\s*$'
}

# trim <string>
# Strips leading/trailing whitespace.
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  echo "$s"
}
