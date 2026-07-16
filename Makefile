RUSTY_LIB := $(CURDIR)/rusty-slap/target/release
RUSTY_A   := $(RUSTY_LIB)/librusty_slap.a
PREFIX    ?= $(HOME)/.local

# Match system make.conf: compile Rust for the host CPU, so crc32fast picks up CLMUL/PCLMULQDQ at compile time.
export RUSTFLAGS += -C target-cpu=native

.PHONY: all rusty-slap cabal install test haddock wasm wasm-link-check wasm-parity-check rusty-slap-wasm clean

all: rusty-slap cabal

rusty-slap:
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

# Copy the built binary onto your PATH. PREFIX defaults to ~/.local; override it (PREFIX=/usr/local may need sudo).
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

WASM_RUSTY_LIB   := $(CURDIR)/rusty-slap/target/wasm32-wasip1/release
WASM_RUSTY_A     := $(WASM_RUSTY_LIB)/librusty_slap.a
WASM_CABAL_FLAGS := --project-file=cabal.project.wasm32-wasi --builddir=dist-newstyle-wasm

# Compile rusty-slap for the wasm target. RUSTFLAGS is emptied because the host-CPU tuning above means nothing to wasm32.
rusty-slap-wasm:
	cd rusty-slap && RUSTFLAGS='' cargo build --release --target wasm32-wasip1

# Cross-compile slap-internal with the ghc-wasm toolchain (~/.ghc-wasm, installed by ghc-wasm-meta); needs the vendor/ram submodule.
# The stale-staticlib trap from the cabal target, mirrored: a fresh wasm .a forces a clean of the wasm builddir.
wasm: rusty-slap-wasm
	@if [ ! -f $(HOME)/.ghc-wasm/env ]; then echo "make wasm needs the ghc-wasm toolchain at ~/.ghc-wasm (see ghc-wasm-meta)"; exit 1; fi
	@if [ ! -f vendor/ram/ram.cabal ]; then git submodule update --init vendor/ram; fi
	@desired='extra-lib-dirs: $(WASM_RUSTY_LIB)'; \
	 if [ ! -f cabal.project.wasm32-wasi.local ] || [ "$$(cat cabal.project.wasm32-wasi.local)" != "$$desired" ]; then \
	   printf '%s\n' "$$desired" > cabal.project.wasm32-wasi.local; \
	 fi
	@if [ ! -f .rusty-wasm-stamp ] || [ $(WASM_RUSTY_A) -nt .rusty-wasm-stamp ]; then \
	  rm -rf dist-newstyle-wasm; touch .rusty-wasm-stamp; \
	fi
	. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal build slap-internal $(WASM_CABAL_FLAGS)

# Link the reactor over slap-web and prove one value survives the crossing: the JS host checks the CRC-32 of "123456789".
wasm-link-check: wasm
	. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal build slap-web-reactor $(WASM_CABAL_FLAGS)
	. $(HOME)/.ghc-wasm/env && node web-reactor/host.mjs "$$(wasm32-wasi-cabal -v0 list-bin slap-web-reactor $(WASM_CABAL_FLAGS))"

# Native and wasm inspect the same patches and must speak byte-identical envelopes; cmp judges.
# Sweeps every dm4y fixture (one patch per format) plus a non-patch, so a refusal envelope crosses too.
wasm-parity-check: cabal wasm
	. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal build slap-web-reactor $(WASM_CABAL_FLAGS)
	@probe="$$(cabal -v0 list-bin slap-web-reactor)"; \
	 reactor="$$(. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal -v0 list-bin slap-web-reactor $(WASM_CABAL_FLAGS))"; \
	 workdir="$$(mktemp -d)"; trap 'rm -rf "$$workdir"' EXIT; \
	 agree() { "$$probe" "$$@" > "$$workdir/native.json"; \
	           node web-reactor/envelope-host.mjs "$$reactor" "$$@" > "$$workdir/wasm.json"; \
	           cmp "$$workdir/native.json" "$$workdir/wasm.json" || { echo "envelope parity FAILED on $$*"; exit 1; }; \
	           echo "envelope parity holds on $$*"; }; \
	 printf 'not a patch' > "$$workdir/unrecognized"; \
	 agree surface; \
	 for patch in test/data/dm4y/patch.* "$$workdir/unrecognized"; do \
	   agree inspect "$$patch"; \
	   agree analyze "$$patch"; \
	 done; \
	 agree check-apply   test/data/dm4y/patch.bps test/data/dm4y/base.gbc  test/data/web/apply.json; \
	 agree check-undo    test/data/dm4y/patch.bps test/data/dm4y/base.gbc  test/data/web/undo.json; \
	 agree check-create  test/data/dm4y/base.gbc  test/data/dm4y/patch.bps test/data/web/create.json; \
	 agree check-convert test/data/dm4y/patch.bps test/data/web/convert.json; \
	 agree check-convert test/data/dm4y/patch.ips test/data/web/convert.json; \
	 agree check-convert test/data/dm4y/patch.bps test/data/web/convert-with-source.json test/data/dm4y/base.gbc; \
	 agree apply   test/data/dm4y/patch.bps test/data/dm4y/base.gbc  test/data/web/apply.json; \
	 agree undo    test/data/dm4y/patch.bps test/data/dm4y/base.gbc  test/data/web/undo.json; \
	 "$$(cabal -v0 list-bin slap)" apply test/data/dm4y/patch.ups test/data/dm4y/base.gbc -o "$$workdir/patched-by-ups.gbc" > /dev/null; \
	 agree undo    test/data/dm4y/patch.ups "$$workdir/patched-by-ups.gbc" test/data/web/undo.json; \
	 agree create  test/data/dm4y/patch.ips test/data/dm4y/patch.ups test/data/web/create.json; \
	 agree convert test/data/dm4y/patch.bps test/data/web/convert.json; \
	 agree convert test/data/dm4y/patch.ips test/data/web/convert.json; \
	 agree convert test/data/dm4y/patch.bps test/data/web/convert-with-source.json test/data/dm4y/base.gbc

# Scrub 🧼
clean:
	cd rusty-slap && cargo clean
	cabal clean
	rm -rf dist-newstyle-wasm
	rm -f .rusty-stamp .rusty-wasm-stamp