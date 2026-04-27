RUSTY_LIB := $(CURDIR)/rusty-slap/target/release
RUSTY_A   := $(RUSTY_LIB)/librusty_slap.a

# Match system make.conf: compile Rust for the host CPU so crc32fast
# picks up CLMUL/PCLMULQDQ at compile time.
export RUSTFLAGS += -C target-cpu=native

.PHONY: all rusty-slap cabal test clean

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
	cabal build

# Run every test: props (QuickCheck + spec conformance) and the full
# integration suite.  Depends on `cabal` (not just `rusty-slap`) so the
# `slap` executable is built before the integration suite spawns it via
# `cabal list-bin slap`.  The rusty-stamp / relink dance lives in the
# `cabal` target and runs once for both build and test.
#
# The integration suite writes one CSV row per test case via the
# bundled csvReporter ingredient.  $SLAP_TEST_RESULTS overrides the
# directory; new files are written per run, accumulating in there
# until the user prunes.
SLAP_TEST_RESULTS ?= test-results
test: cabal
	@mkdir -p $(SLAP_TEST_RESULTS)
	cabal test props
	cabal test integration --test-options="--csv=$(SLAP_TEST_RESULTS)/integration-$$(date +%Y%m%d-%H%M%S).csv"

# Run only the QuickCheck/property/conformance suite. Fast.
props: cabal
	cabal test props

# Run only the integration suite (spawns the real `slap` binary
# against fixture patches). Slower than `props`.
integration: cabal
	@mkdir -p $(SLAP_TEST_RESULTS)
	cabal test integration --test-options="--csv=$(SLAP_TEST_RESULTS)/integration-$$(date +%Y%m%d-%H%M%S).csv"


# Generate Haddock, if you're into that sort of thing.
haddock: cabal
	cabal haddock slap-internal

clean:
	cd rusty-slap && cargo clean
	cabal clean
	rm -f .rusty-stamp
