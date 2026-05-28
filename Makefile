RUSTY_LIB := $(CURDIR)/rusty-slap/target/release
RUSTY_A   := $(RUSTY_LIB)/librusty_slap.a
PREFIX    ?= $(HOME)/.local

# Match system make.conf: compile Rust for the host CPU so crc32fast
# picks up CLMUL/PCLMULQDQ at compile time.
export RUSTFLAGS += -C target-cpu=native

.PHONY: all rusty-slap cabal install test test-onecore haddock clean

all: rusty-slap cabal

rusty-slap:
	cd rusty-slap && cargo build --release

# Point cabal at the rusty-slap staticlib via a gitignored
# cabal.project.local derived from $(CURDIR). A project-local file -- not a
# LIBRARY_PATH that only make sets -- means *every* cabal invocation (cabal
# run/test/install, not just make) can link rusty_slap, so a bare `cabal
# run slap` right after a source edit doesn't fail to find it. Rewritten
# only when the path changes, so it never triggers a spurious reconfigure.
#
# Separately: an external .a pulled in via extra-libraries isn't one of the
# source inputs cabal tracks to decide what to rebuild, so when only the
# Rust side changes cabal sees no reason to relink. A stamp plus cabal
# clean is the only reliable way to pick up a freshly built static library.
cabal: rusty-slap
	@desired='extra-lib-dirs: $(RUSTY_LIB)'; \
	 if [ ! -f cabal.project.local ] || [ "$$(cat cabal.project.local)" != "$$desired" ]; then \
	   printf '%s\n' "$$desired" > cabal.project.local; \
	 fi
	@if [ ! -f .rusty-stamp ] || [ $(RUSTY_A) -nt .rusty-stamp ]; then \
	  cabal clean 2>/dev/null; touch .rusty-stamp; \
	fi
	cabal build

# Install the built binary onto your PATH. PREFIX defaults to ~/.local;
# override it (e.g. PREFIX=/usr/local, which may need sudo). The Rust core
# is statically baked in, so this is a plain copy of a self-contained
# binary: no relink, which is why it just rides on the `cabal` target.
install: cabal
	mkdir -p "$(DESTDIR)$(PREFIX)/bin"
	cp "$$(cabal -v0 list-bin slap)" "$(DESTDIR)$(PREFIX)/bin/slap"
	@echo "installed slap to $(DESTDIR)$(PREFIX)/bin/slap"

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