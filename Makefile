RUSTY_LIB := $(CURDIR)/rusty-slap/target/release
RUSTY_A   := $(RUSTY_LIB)/librusty_slap.a
PREFIX    ?= $(HOME)/.local

# Match system make.conf: compile Rust for the host CPU,
# so crc32fast picks up CLMUL/PCLMULQDQ at compile time.
export RUSTFLAGS += -C target-cpu=native

.PHONY: all rusty-slap cabal install test haddock clean

all: rusty-slap cabal

# The lzma-rust2 fork rides as a submodule;
# a fresh clone needs it before cargo can see the path dependency.
rusty-slap:
	@if [ ! -f rusty-slap/vendor/lzma-rust2/Cargo.toml ]; then \
	  git submodule update --init rusty-slap/vendor/lzma-rust2; \
	fi
	cd rusty-slap && cargo build --release

# Write cabal.project.local so cabal finds the staticlib.
# cabal doesn't track the .a as an input, so a Rust-only change won't relink on its own.
# .rusty-stamp forces a clean when the .a is newer.
cabal: rusty-slap
	@desired='extra-lib-dirs: $(RUSTY_LIB)'; \
	 if [ ! -f cabal.project.local ] || [ "$$(cat cabal.project.local)" != "$$desired" ]; then \
	   printf '%s\n' "$$desired" > cabal.project.local; \
	 fi
	@if [ ! -f .rusty-stamp ] || [ $(RUSTY_A) -nt .rusty-stamp ]; then \
	  cabal clean 2>/dev/null; touch .rusty-stamp; \
	fi
	cabal build

# Copy the built binary onto your PATH. PREFIX defaults to ~/.local;
# override it (PREFIX=/usr/local may need sudo).
install: cabal
	mkdir -p "$(DESTDIR)$(PREFIX)/bin"
	cp "$$(cabal -v0 list-bin slap)" "$(DESTDIR)$(PREFIX)/bin/slap"
	@echo "installed slap to $(DESTDIR)$(PREFIX)/bin/slap"

SLAP_TEST_RESULTS ?= test-results

# Run all the tests. Done using one core so as to actually track per-test execution time.
test: cabal
	@mkdir -p $(SLAP_TEST_RESULTS)
	cabal test props
	cabal test integration --test-options="--num-threads=1 --stats=$(SLAP_TEST_RESULTS)/test-$$(date +%Y%m%d-%H%M%S).csv"

# Generate Haddock, if you're into that sort of thing.
haddock: cabal
	cabal haddock slap-internal

# Scrub 🧼
clean:
	cd rusty-slap && cargo clean
	cabal clean
	rm -f .rusty-stamp