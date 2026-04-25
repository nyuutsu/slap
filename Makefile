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
test: cabal
	cabal test

clean:
	cd rusty-slap && cargo clean
	cabal clean
	rm -f .rusty-stamp
