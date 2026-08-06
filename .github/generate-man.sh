#!/bin/sh
# Write slap's man page from the binary's own words: the front page, then a COMMANDS section holding
# every command's --help verbatim. The command roster is read from the binary too, so nothing can drift.
#
#   .github/generate-man.sh SLAP-BINARY OUTPUT.1
set -eu
slapBinary="$1"
manOutput="$2"

commandRoster="$("$slapBinary" --help | awk '
  /Available commands/ { scanning = 1; next }
  /Quick start/         { scanning = 0 }
  scanning && /^ +[a-z-]+($| )/ { print $1 }')"
[ -n "$commandRoster" ] || { echo "generate-man.sh: found no commands in $slapBinary --help" >&2; exit 1; }

sectionFile="$(mktemp)"
trap 'rm -f "$sectionFile"' EXIT

printf '[COMMANDS]\n' > "$sectionFile"
for commandName in $commandRoster; do
  printf '.SS "slap %s"\n.nf\n' "$commandName" >> "$sectionFile"
  # \& in front of each line keeps roff from reading help text as its own commands
  "$slapBinary" "$commandName" --help | sed 's/\\/\\\\/g; s/^/\\\&/' >> "$sectionFile"
  printf '.fi\n' >> "$sectionFile"
done

help2man --no-info --name 'multi-format ROM patching tool' --include "$sectionFile" --output "$manOutput" "$slapBinary"
