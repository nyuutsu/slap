RUSTY_LIB := $(CURDIR)/rusty-slap/target/release
RUSTY_A   := $(RUSTY_LIB)/librusty_slap.a

# Match system make.conf: compile Rust for the host CPU so crc32fast
# picks up CLMUL/PCLMULQDQ at compile time.
export RUSTFLAGS += -C target-cpu=native

# Top-level test groups inside the integration-full binary. Each one runs
# in its own OS process under `make test-full` so they get separate GHC
# heaps, separate GCs, and crash isolation. Names must match the literal
# group strings used in test/Integration/*.hs.
TEST_GROUPS        := apply create crossval convert metadata undo cli failure-mode
TEST_GROUP_TARGETS := $(addprefix test-full-,$(TEST_GROUPS))

.PHONY: all rusty-slap cabal test test-full test-full-quick test-full-build \
        test-full-groups $(TEST_GROUP_TARGETS) clean

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

test: rusty-slap
	@if [ ! -f .rusty-stamp ] || [ $(RUSTY_A) -nt .rusty-stamp ]; then \
	  cabal clean 2>/dev/null; touch .rusty-stamp; \
	fi
	cabal test --extra-lib-dirs=$(RUSTY_LIB)

# Heavy integration tier: stadium2, cross-validation against third-party
# tools, failure-mode subprocesses with multi-MB scratch files. Gated
# behind the heavy-tests cabal flag so it never runs on a bare `cabal test`.
#
# Each top-level test group runs in its own OS process so they get
# separate GHC heaps, separate GCs, and crash isolation. The whole thing
# is staged in three phases:
#
#   1. test-full-quick  — run the everyday quick tier (props + integration)
#   2. test-full-build  — build the integration-full binary exactly once
#   3. test-full-groups — recurse with -j, dispatching one process per
#                         group via tasty's -p filter
#
# Phases 1 and 2 must finish before phase 3, because cabal can't be
# invoked from multiple parallel make jobs without lockfile conflicts.
test-full: test-full-quick test-full-build
	@$(MAKE) -j$(words $(TEST_GROUPS)) --output-sync=target test-full-groups

test-full-quick: rusty-slap
	@if [ ! -f .rusty-stamp ] || [ $(RUSTY_A) -nt .rusty-stamp ]; then \
	  cabal clean 2>/dev/null; touch .rusty-stamp; \
	fi
	cabal test --extra-lib-dirs=$(RUSTY_LIB)

test-full-build: rusty-slap
	@if [ ! -f .rusty-stamp ] || [ $(RUSTY_A) -nt .rusty-stamp ]; then \
	  cabal clean 2>/dev/null; touch .rusty-stamp; \
	fi
	cabal build --extra-lib-dirs=$(RUSTY_LIB) --flag heavy-tests integration-full

test-full-groups: $(TEST_GROUP_TARGETS)

# Each per-group target runs the integration-full binary filtered to one
# top-level group via tasty's awk-style pattern. We anchor on $2 (the
# second path component) rather than a substring match because some
# group names appear inside test case names elsewhere — e.g. the cli
# group has tests literally named "create/...", which would collide with
# a naive /create/ regex.
$(TEST_GROUP_TARGETS): test-full-%:
	@BIN=$$(cabal list-bin --extra-lib-dirs=$(RUSTY_LIB) --flag heavy-tests integration-full); \
	echo "==> test-full-$*"; \
	"$$BIN" -p '$$2 == "$*"'

clean:
	cd rusty-slap && cargo clean
	cabal clean
	rm -f .rusty-stamp
