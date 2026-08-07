#!/bin/sh
# Assemble one release archive from the binary its lane has already finished: slap-VERSION-PLATFORM.tar.gz, or .zip for windows.
# The man page and completions are generated from that very binary, so they cannot drift from it.
#
#   .github/assemble-release.sh x86_64-linux
set -eu
platform="$1"

# a workflow_dispatch run has no tag to be named after; its archives say dev
case "${GITHUB_REF:-}" in refs/tags/*) version="${GITHUB_REF_NAME#v}" ;; *) version="dev" ;; esac

slapBinary="$(cabal -v0 list-bin exe:slap --project-file=cabal.project.release)"
# on windows, cabal speaks backslashes that this shell cannot follow
command -v cygpath > /dev/null 2>&1 && slapBinary="$(cygpath -u "$slapBinary")"
# a strip refusal leaves a heavier, still-correct binary
strip "$slapBinary" 2>/dev/null || true
ls -l "$slapBinary"

stageName="slap-$version-$platform"
mkdir "$stageName" "$stageName/completions"
case "$platform" in
  *windows*)
    cp "$slapBinary" "$stageName/slap.exe"
    cp "$(find "$(cygpath -u "$(ghc --print-libdir)")/.." -name libunwind.dll | head -n 1)" "$stageName/"
    ;;
  *) cp "$slapBinary" "$stageName/slap" ;;
esac
cp LICENSE "$stageName/"
if command -v help2man >/dev/null 2>&1; then
  .github/generate-man.sh "$slapBinary" "$stageName/slap.1"
fi
# the completions embed a bare slap, found via PATH; unlike make install, this archive cannot know where the binary will land
"$slapBinary" --bash-completion-script slap > "$stageName/completions/slap.bash"
"$slapBinary" --zsh-completion-script  slap > "$stageName/completions/_slap"
"$slapBinary" --fish-completion-script slap > "$stageName/completions/slap.fish"

case "$platform" in
  *windows*)
    cat > "$stageName/INSTALL.txt" <<'EOF'
slap is slap.exe plus libunwind.dll, which must stay beside it; put the pair anywhere on your PATH.
Using bash on windows? completions/slap.bash can be sourced from your .bashrc.
EOF
    ;;
  *)
    cp .github/install.sh "$stageName/install.sh"
    cat > "$stageName/INSTALL.txt" <<'EOF'
The quick version: put ./slap anywhere on your PATH. That's the whole tool.

Or run ./install.sh, which puts slap in ~/.local/bin and places the man page
and shell completions where your shells look for them.
EOF
    ;;
esac
case "$platform" in
  *macos*)
    cat >> "$stageName/INSTALL.txt" <<'EOF'

If a browser downloaded this archive, macOS may quarantine the binary; this clears it:
  xattr -d com.apple.quarantine slap
(install.sh does this for you.)
EOF
    ;;
esac

case "$platform" in
  *windows*) 7z a "$stageName.zip" "$stageName" > /dev/null ;;
  *)         tar czf "$stageName.tar.gz" "$stageName" ;;
esac
