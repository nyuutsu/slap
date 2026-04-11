RUSTY_LIB := $(CURDIR)/rusty-slap/target/release
RUSTY_A   := $(RUSTY_LIB)/librusty_slap.a

# Match system make.conf: compile Rust for the host CPU so crc32fast
# picks up CLMUL/PCLMULQDQ at compile time.
export RUSTFLAGS += -C target-cpu=native

# Top-level test groups inside the integration-full binary. Each one runs
# in its own OS process under `make test` so they get separate GHC
# heaps, separate GCs, and crash isolation. Names must match the literal
# group strings used in test/Integration/*.hs.
TEST_GROUPS        := apply create crossval convert metadata undo cli failure-mode
TEST_GROUP_TARGETS := $(addprefix test-heavy-,$(TEST_GROUPS))

.PHONY: all rusty-slap cabal test test-quick test-heavy-build \
        test-heavy-check-groups test-heavy-groups $(TEST_GROUP_TARGETS) clean

all: rusty-slap cabal

rusty-slap:
	cd rusty-slap && cargo build --release

# Cabal doesn't track changes to external .a files, and cabal 3.14
# uses content hashing so touching FFI.hs doesn't force a relink.
# When the Rust .a changes, cabal clean is the only reliable way to
# pick up the new static library.
cabal: rusty-slap
	@if [ ! -f .rusty-stamp ] || [ $(RUSTY_A) -nt .rusty-stamp ]; then \
	  cabal clean 2>/dev/null; touch .rusty-stamp; \
	fi
	cabal build --extra-lib-dirs=$(RUSTY_LIB)

# `make test` runs EVERYTHING: the quick tier (props + integration),
# then the heavy tier (stadium2, cross-validation against third-party
# tools, failure-mode subprocesses with multi-MB scratch files). The
# heavy tier is gated behind the heavy-tests cabal flag so a bare
# `cabal test` never runs it.
#
# Each top-level heavy test group runs in its own OS process so they
# get separate GHC heaps, separate GCs, and crash isolation. The whole
# thing is staged in three phases:
#
#   1. test-quick              — run the everyday quick tier
#                                (props + integration)
#   2. test-heavy-build        — build the integration-full binary
#                                exactly once
#   3. test-heavy-groups       — recurse with -j, dispatching one
#                                process per group via tasty's -p filter
#
# Phases 1 and 2 must finish before phase 3, because cabal can't be
# invoked from multiple parallel make jobs without lockfile conflicts.
# A cheap sanity check runs between phases 2 and 3 to catch the
# footgun where someone adds a new top-level test group in Haskell
# and forgets to update TEST_GROUPS — see test-heavy-check-groups.
test: test-quick test-heavy-build test-heavy-check-groups
	@$(MAKE) -j$(words $(TEST_GROUPS)) --output-sync=target test-heavy-groups

# `make test-quick` runs only the quick tier: the props suite
# (QuickCheck + spec conformance) and the integration suite filtered
# to tests that don't touch the heavy ROMs (stadium2, paper-mario).
# Finishes in under 5 seconds on this machine. Use this during tight
# development loops when the heavy tier's ~2 minutes is too long.
test-quick: rusty-slap
	@if [ ! -f .rusty-stamp ] || [ $(RUSTY_A) -nt .rusty-stamp ]; then \
	  cabal clean 2>/dev/null; touch .rusty-stamp; \
	fi
	cabal test --extra-lib-dirs=$(RUSTY_LIB)

test-heavy-build: rusty-slap
	@if [ ! -f .rusty-stamp ] || [ $(RUSTY_A) -nt .rusty-stamp ]; then \
	  cabal clean 2>/dev/null; touch .rusty-stamp; \
	fi
	cabal build --extra-lib-dirs=$(RUSTY_LIB) --flag heavy-tests integration-full

# Sanity-check that TEST_GROUPS above stays in sync with the canonical
# 'topLevelGroupNames' constant in test/Integration/Runner.hs. Without
# this, adding a new top-level group in Haskell would silently skip it
# under `make test`: the per-group dispatch only iterates the
# hardcoded TEST_GROUPS list, so a missing entry means the new group's
# tests never run, while the suite still reports green.
#
# We sort both sides because TEST_GROUPS is ordered for human reading,
# not for diffing. On mismatch we name both files so the fix is obvious.
test-heavy-check-groups: test-heavy-build
	@BIN=$$(cabal list-bin --extra-lib-dirs=$(RUSTY_LIB) --flag heavy-tests integration-full); \
	expected=$$("$$BIN" --list-groups | sort | tr '\n' ' '); \
	actual=$$(printf '%s\n' $(TEST_GROUPS) | sort | tr '\n' ' '); \
	if [ "$$expected" != "$$actual" ]; then \
	  echo "TEST_GROUPS in Makefile is out of sync with"; \
	  echo "Integration.Runner.topLevelGroupNames."; \
	  echo "  Makefile  : $$actual"; \
	  echo "  Haskell   : $$expected"; \
	  echo "Update both lists so they match:"; \
	  echo "  - Makefile (TEST_GROUPS)"; \
	  echo "  - test/Integration/Runner.hs (topLevelGroupNames)"; \
	  exit 1; \
	fi

test-heavy-groups: $(TEST_GROUP_TARGETS)

# Each per-group target runs the integration-full binary filtered to one
# top-level group via tasty's awk-style pattern. We anchor on $2 (the
# second path component) rather than a substring match because some
# group names appear inside test case names elsewhere — e.g. the cli
# group has tests literally named "create/...", which would collide with
# a naive /create/ regex.
#
# Three layers of dollar-sign evaluation, each by a different evaluator:
#   $$BIN — shell expansion of the BIN variable set on the previous line
#           (the doubled $$ escapes make's own expansion so the literal
#           "$BIN" reaches the shell)
#   $$2   — awk-style field reference, evaluated by tasty's pattern
#           parser at test-runtime; refers to the second path component
#           of each test name
#   $*    — GNU make's stem expansion from the test-heavy-% pattern rule,
#           e.g. "apply" when the target is test-heavy-apply
$(TEST_GROUP_TARGETS): test-heavy-%:
	@BIN=$$(cabal list-bin --extra-lib-dirs=$(RUSTY_LIB) --flag heavy-tests integration-full); \
	echo "==> test-heavy-$*"; \
	"$$BIN" -p '$$2 == "$*"'

clean:
	cd rusty-slap && cargo clean
	cabal clean
	rm -f .rusty-stamp
