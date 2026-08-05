#!/bin/sh
# The whole linux lane, run inside an alpine container by the release rig: toolchain, rusty-slap,
# a static slap at the release flavor, props, and the finished archive.
# The container is an explicit docker run rather than a job container so the same recipe serves
# x86_64 and aarch64: GitHub's runner cannot host JS actions inside an arm alpine container.
#
#   .github/build-linux.sh PLATFORM    (x86_64-linux | aarch64-linux)
set -eu
platform="$1"

apk add --no-cache bash curl git tar xz make gcc g++ musl-dev binutils file \
  gmp-dev ncurses-dev zlib-dev zlib-static libffi-dev perl help2man

# the ghcup binary is itself static, so it runs here; on alpine it selects the musl bindists
curl -fsSL "https://downloads.haskell.org/~ghcup/$(uname -m)-linux-ghcup" -o /usr/local/bin/ghcup
chmod +x /usr/local/bin/ghcup
ghcup install ghc "$GHC_VERSION" --set
ghcup install cabal recommended --set
PATH="$HOME/.ghcup/bin:$PATH"

curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs | sh -s -- -y --profile minimal
PATH="$HOME/.cargo/bin:$PATH"

# RUSTFLAGS is empty here and in every lane: the Makefile's target-cpu=native is for the dev machine,
# and a release runs on whatever CPU a stranger owns
RUSTFLAGS='' cargo build --release --locked --manifest-path rusty-slap/Cargo.toml

printf 'extra-lib-dirs: %s/rusty-slap/target/release\n' "$PWD" > cabal.project.release.local
cabal update
cabal build exe:slap --project-file=cabal.project.release --enable-executable-static --ghc-options=-split-sections
file "$(cabal -v0 list-bin exe:slap --project-file=cabal.project.release)" | grep -q 'statically linked'

# props only: the integration suite reads ROMs that cannot be in CI; it stays make test's job
cabal test props --project-file=cabal.project.release --enable-executable-static --ghc-options=-split-sections --test-show-details=direct

.github/assemble-release.sh "$platform"
