#!/usr/bin/env bash
# slap test library — shared helpers for all test modules
# Sourced by run.sh; not meant to be run standalone.

pass=0
fail=0
skip=0

TMPDIR_BASE=$(mktemp -d -p "${SLAP_TMPDIR:-${TMPDIR:-/tmp}}" slap-test.XXXXXX)
cleanup() { rm -rf "$TMPDIR_BASE"; }
trap cleanup EXIT

mktmp() {
  mktemp -p "$TMPDIR_BASE"
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

# expect_success <label> <cmd...>
# Expects zero exit (don't check output).
expect_success() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    ok "$name"
  else
    bad "$name" "command failed"
  fi
}

# bootstrap <base> <patch> → prints tmp path to patched file
# Fatal on failure.
bootstrap() {
  local base="$1" patch="$2"
  local target; target=$(mktmp)
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
# Reads a matrix file, strips comments and blank lines.
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
