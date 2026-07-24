RUSTY_LIB := $(CURDIR)/rusty-slap/target/release
RUSTY_A   := $(RUSTY_LIB)/librusty_slap.a
PREFIX    ?= $(HOME)/.local

# Match system make.conf: compile Rust for the host CPU. This Makefile builds slap for the machine it runs on.
export RUSTFLAGS += -C target-cpu=native

# Two flavors, one dist-newstyle. `make` iterates at -O0 with info-table provenance (both declared in cabal.project);
# `make optimized` asks for -O2, which cabal keeps in its own output directory, so the flavors never disturb each other.
.PHONY: all build optimized rusty-slap staticlib-wiring install man test haddock wasm wasm-optimized wasm-staticlib-wiring wasm-link-check wasm-parity-check wasm-worker-rig rusty-slap-wasm web web-optimized web-bake-surface web-check web-rig web-deploy clean

all: build

rusty-slap:
	cd rusty-slap && cargo build --release

# Write cabal.project.local so cabal finds the staticlib.
# cabal doesn't track the .a as an input, so a Rust-only change won't relink on its own.
# .rusty-stamp forces a clean when the .a is newer.
staticlib-wiring: rusty-slap
	@desired='extra-lib-dirs: $(RUSTY_LIB)'; \
	 if [ ! -f cabal.project.local ] || [ "$$(cat cabal.project.local)" != "$$desired" ]; then \
	   printf '%s\n' "$$desired" > cabal.project.local; \
	 fi
	@if [ ! -f .rusty-stamp ] || [ $(RUSTY_A) -nt .rusty-stamp ]; then \
	  cabal clean 2>/dev/null; touch .rusty-stamp; \
	fi

build: staticlib-wiring
	cabal build

# The slap binary at -O2, for benchmarking and for `install`.
optimized: staticlib-wiring
	cabal build exe:slap -O2

# Copy the optimized binary onto your PATH. PREFIX defaults to ~/.local; override it (PREFIX=/usr/local may need sudo).
install: optimized
	mkdir -p "$(DESTDIR)$(PREFIX)/bin"
	cp "$$(cabal -v0 list-bin -O2 slap)" "$(DESTDIR)$(PREFIX)/bin/slap"
	@echo "installed slap to $(DESTDIR)$(PREFIX)/bin/slap"
	@if command -v help2man >/dev/null 2>&1; then \
	  mkdir -p "$(DESTDIR)$(PREFIX)/share/man/man1"; \
	  help2man --no-info --name 'multi-format ROM patching tool' --output="$(DESTDIR)$(PREFIX)/share/man/man1/slap.1" "$$(cabal -v0 list-bin -O2 slap)"; \
	  echo "installed man page to $(DESTDIR)$(PREFIX)/share/man/man1/slap.1"; \
	else \
	  echo "help2man not found; skipping man page (emerge dev-util/help2man to include it)"; \
	fi

# Generate slap.1 from the built binary's --help/--version (help2man, so it never drifts). View with: man ./slap.1
man: build
	@command -v help2man >/dev/null 2>&1 || { echo "make man needs help2man (emerge dev-util/help2man)"; exit 1; }
	help2man --no-info --name 'multi-format ROM patching tool' --output=slap.1 "$$(cabal -v0 list-bin slap)"
	@echo "wrote slap.1  (view with: man ./slap.1)"

SLAP_TEST_RESULTS ?= test-results

# Run all the tests. Done using one core so as to actually track per-test execution time.
test: build
	@mkdir -p $(SLAP_TEST_RESULTS)
	cabal test props
	cabal test integration --test-options="--num-threads=1 --stats=$(SLAP_TEST_RESULTS)/test-$$(date +%Y%m%d-%H%M%S).csv"

# Generate Haddock, if you're into that sort of thing.
haddock: build
	cabal haddock slap-internal

WASM_RUSTY_LIB   := $(CURDIR)/rusty-slap/target/wasm32-wasip1/release
WASM_RUSTY_A     := $(WASM_RUSTY_LIB)/librusty_slap.a
WASM_CABAL_FLAGS := --project-file=cabal.project.wasm32-wasi --builddir=dist-newstyle-wasm

# Compile rusty-slap for the wasm target. RUSTFLAGS is emptied because the host-CPU tuning above means nothing to wasm32.
rusty-slap-wasm:
	cd rusty-slap && RUSTFLAGS='' cargo build --release --target wasm32-wasip1

# staticlib-wiring's wasm mirror, with the stale-staticlib trap handled the same way: a fresh wasm .a forces a clean of the wasm builddir.
wasm-staticlib-wiring: rusty-slap-wasm
	@if [ ! -f $(HOME)/.ghc-wasm/env ]; then echo "make wasm needs the ghc-wasm toolchain at ~/.ghc-wasm (see ghc-wasm-meta)"; exit 1; fi
	@if [ ! -f vendor/ram/ram.cabal ]; then git submodule update --init vendor/ram; fi
	@desired='extra-lib-dirs: $(WASM_RUSTY_LIB)'; \
	 if [ ! -f cabal.project.wasm32-wasi.local ] || [ "$$(cat cabal.project.wasm32-wasi.local)" != "$$desired" ]; then \
	   printf '%s\n' "$$desired" > cabal.project.wasm32-wasi.local; \
	 fi
	@if [ ! -f .rusty-wasm-stamp ] || [ $(WASM_RUSTY_A) -nt .rusty-wasm-stamp ]; then \
	  rm -rf dist-newstyle-wasm; touch .rusty-wasm-stamp; \
	fi

# Cross-compile slap-internal with the ghc-wasm toolchain (~/.ghc-wasm, installed by ghc-wasm-meta); needs the vendor/ram submodule.
wasm: wasm-staticlib-wiring
	. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal build slap-internal $(WASM_CABAL_FLAGS)

# The browser artifact at -O2, for measuring what visitors would actually run.
wasm-optimized: wasm-staticlib-wiring
	. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal build slap-web-reactor -O2 $(WASM_CABAL_FLAGS)
	@echo "optimized reactor at $$(. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal -v0 list-bin slap-web-reactor -O2 $(WASM_CABAL_FLAGS))"

# Link the reactor over slap-web and prove one value survives the crossing: the JS host checks the CRC-32 of "123456789".
wasm-link-check: wasm
	. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal build slap-web-reactor $(WASM_CABAL_FLAGS)
	. $(HOME)/.ghc-wasm/env && node web-reactor/host.mjs "$$(wasm32-wasi-cabal -v0 list-bin slap-web-reactor $(WASM_CABAL_FLAGS))"

# Native and wasm inspect the same patches and must speak byte-identical envelopes; cmp judges.
# Sweeps every dm4y fixture (one patch per format) plus a non-patch, so a refusal envelope crosses too.
wasm-parity-check: build wasm
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
	 agree describe-rom test/data/dm4y/base.gbc; \
	 for patch in test/data/dm4y/patch.* "$$workdir/unrecognized"; do \
	   agree classify "$$patch"; \
	   agree identify "$$patch" test/data/web/identify.json; \
	   agree inspect "$$patch" test/data/web/inspect.json; \
	   agree analyze "$$patch" test/data/web/analyze.json; \
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

# Serve the Worker shell's check, run by hand in a browser; worker-rig.html says what to watch for.
wasm-worker-rig: wasm
	@if [ ! -f vendor/browser_wasi_shim/dist/index.js ]; then git submodule update --init vendor/browser_wasi_shim; fi
	. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal build slap-web-reactor $(WASM_CABAL_FLAGS)
	cp "$$(. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal -v0 list-bin slap-web-reactor $(WASM_CABAL_FLAGS))" web-reactor/slap-web-reactor.wasm
	@echo "the rig is at http://127.0.0.1:8000/web-reactor/worker-rig.html"
	@python3 -m http.server --bind 127.0.0.1 8000

# Assemble the page and its reactor into dist-web/ — the tree slap.nyuu.page serves verbatim.
# `make web` carries the everyday -O0 reactor for quick iteration; the deploy ships the -O2 one,
# which runs the heavy analyses at full speed and weighs half as much on the wire.
# The stamp keeps describe to hash and "-dirty": a tag name could carry an apostrophe into the stamp's quoted JS literal.
define assemble-web
	@if [ ! -f vendor/browser_wasi_shim/dist/index.js ]; then git submodule update --init vendor/browser_wasi_shim; fi
	rm -rf dist-web
	mkdir -p dist-web/reactor dist-web/vendor/browser_wasi_shim
	cp -r web-page/. dist-web/
	printf "export const buildStamp = 'this page was built on %s (%s)';\n" "$$(date +%F)" "$$(git describe --always --dirty --exclude='*')" > dist-web/page/build-stamp.mjs
	cp web-reactor/reactor-client.mjs web-reactor/envelope-worker.mjs dist-web/reactor/
	cp "$$(. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal -v0 list-bin slap-web-reactor $(1) $(WASM_CABAL_FLAGS))" dist-web/reactor/slap-web-reactor.wasm
	cp -r vendor/browser_wasi_shim/dist dist-web/vendor/browser_wasi_shim/
	node web-page/bake-service-worker.mjs dist-web "$$(git describe --always --dirty --exclude='*')"
	cd dist-web && node boot-check.mjs
endef

web: wasm
	. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal build slap-web-reactor $(WASM_CABAL_FLAGS)
	$(call assemble-web,)

web-optimized: wasm
	. $(HOME)/.ghc-wasm/env && wasm32-wasi-cabal build slap-web-reactor -O2 $(WASM_CABAL_FLAGS)
	$(call assemble-web,-O2)

# The stage furniture's rosters, spoken by the engine and baked into a page module; rebake when the census says they drifted.
web-bake-surface: build
	node web-page/bake-engine-surface.mjs "$$(cabal -v0 list-bin slap-web-reactor)"

# Every fixture's real envelopes through the page's renderers; a shape surprise throws here, not in a browser.
web-check: build
	@workdir="$$(mktemp -d)"; trap 'rm -rf "$$workdir"' EXIT; \
	 printf 'not a patch' > "$$workdir/unrecognized"; \
	 node web-page/check.mjs "$$(cabal -v0 list-bin slap-web-reactor)" test/data/dm4y/base.gbc test/data/dm4y/patch.* "$$workdir/unrecognized"

web-rig: web
	@echo "the page is at http://127.0.0.1:8001/"
	@python3 -m http.server --bind 127.0.0.1 --directory dist-web 8001

# The wasm rides precompressed: Caddy serves the sidecars as-is, so the wire pays brotli's ratio and the droplet no CPU.
# Compression is cached by content digest — an unchanged reactor never pays for brotli -q 11 twice.
web-deploy: web-optimized web-check
	@wasmDigest="$$(sha256sum dist-web/reactor/slap-web-reactor.wasm | cut -d' ' -f1)"; \
	 compressedCache="dist-newstyle-wasm/precompressed"; mkdir -p "$$compressedCache"; \
	 if [ ! -f "$$compressedCache/$$wasmDigest.br" ]; then brotli -q 11 -o "$$compressedCache/$$wasmDigest.br" dist-web/reactor/slap-web-reactor.wasm; fi; \
	 if [ ! -f "$$compressedCache/$$wasmDigest.gz" ]; then gzip -9 -c dist-web/reactor/slap-web-reactor.wasm > "$$compressedCache/$$wasmDigest.gz"; fi; \
	 cp "$$compressedCache/$$wasmDigest.br" dist-web/reactor/slap-web-reactor.wasm.br; \
	 cp "$$compressedCache/$$wasmDigest.gz" dist-web/reactor/slap-web-reactor.wasm.gz
	rsync -az --delete dist-web/ droplet:/var/slap/
	@echo "deployed to https://slap.nyuu.page"

# Scrub 🧼
clean:
	cd rusty-slap && cargo clean
	cabal clean
	rm -rf dist-newstyle-wasm
	rm -f .rusty-stamp .rusty-wasm-stamp
