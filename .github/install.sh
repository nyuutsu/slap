#!/bin/sh
# Ships inside the unix release archives. Installs slap from the archive: the binary,
# its man page, and its shell completions, mirroring what the repo's make install does.
# Everything lands under ~/.local; set PREFIX to choose elsewhere (PREFIX=/usr/local may need sudo).
set -eu
prefix="${PREFIX:-$HOME/.local}"
archiveRoot="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$prefix/bin"
cp -f "$archiveRoot/slap" "$prefix/bin/slap"
echo "installed slap to $prefix/bin/slap"

if [ -f "$archiveRoot/slap.1" ]; then
  mkdir -p "$prefix/share/man/man1"
  cp -f "$archiveRoot/slap.1" "$prefix/share/man/man1/slap.1"
  echo "installed the man page to $prefix/share/man/man1/slap.1"
  # most systems infer this directory from PATH; one that pins MANPATH (gentoo-style env.d) will not
  if command -v man > /dev/null 2>&1 && ! man -w slap > /dev/null 2>&1; then
    printf '%s\n' \
      "  man cannot see it yet, because this system sets MANPATH explicitly; add" \
      "    export MANPATH=\"\$MANPATH:$prefix/share/man\"" \
      "  to your shell setup"
  fi
fi

mkdir -p "$prefix/share/bash-completion/completions" \
         "$prefix/share/zsh/site-functions" \
         "$prefix/share/fish/vendor_completions.d"
cp -f "$archiveRoot/completions/slap.bash" "$prefix/share/bash-completion/completions/slap"
cp -f "$archiveRoot/completions/_slap"     "$prefix/share/zsh/site-functions/_slap"
cp -f "$archiveRoot/completions/slap.fish" "$prefix/share/fish/vendor_completions.d/slap.fish"
echo "installed completions for bash, zsh, and fish under $prefix/share"

case "$prefix" in
  /usr|/usr/local) ;;
  *) printf '%s\n' \
       "bash and fish find these on their own; zsh searches only its fpath, so add" \
       "  fpath=($prefix/share/zsh/site-functions \$fpath)" \
       "to ~/.zshrc, above compinit" ;;
esac

# a browser download arrives quarantined on macOS; installing is as clear a "yes, run this" as exists
case "$(uname)" in
  Darwin) xattr -d com.apple.quarantine "$prefix/bin/slap" 2>/dev/null || true ;;
esac
