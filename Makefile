RUSTY_LIB := $(CURDIR)/rusty-slap/target/release
RUSTY_A   := $(RUSTY_LIB)/librusty_slap.a

# Match system make.conf: compile Rust for the host CPU so crc32fast
# picks up CLMUL/PCLMULQDQ at compile time.
export RUSTFLAGS += -C target-cpu=native

.PHONY: all rusty-slap cabal test test-onecore haddock clean

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

SLAP_TEST_RESULTS ?= test-results

# Run all the tests.
test: cabal
	@mkdir -p $(SLAP_TEST_RESULTS)
	cabal test props
	cabal test integration --test-options="--stats=$(SLAP_TEST_RESULTS)/test-$$(date +%Y%m%d-%H%M%S).csv"

# Run all the tests using one CPU core, thus revealing how long each thing actually needs to take.
test-onecore: cabal
	@mkdir -p $(SLAP_TEST_RESULTS)
	cabal test props
	cabal test integration --test-options="--num-threads=1 --stats=$(SLAP_TEST_RESULTS)/test-onecore-$$(date +%Y%m%d-%H%M%S).csv"

# Generate Haddock, if you're into that sort of thing.
haddock: cabal
	cabal haddock slap-internal

# Scrub 🧼
clean:
	cd rusty-slap && cargo clean
	cabal clean
	rm -f .rusty-stamp