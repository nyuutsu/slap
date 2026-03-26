# slap

Slap is a multi-format ROM patching tool. that auto-detects patch format from
magic bytes.

Apply, create, convert between formats, inspect, and undo patches.
Transparently unwraps ZIP, RAR, and 7z archives containing patches.

## Philosophy

slap does not invent data. Every byte it writes comes from one of three
sources:

1. The inputs you gave it (source file, target file, patch).
2. An explicit choice you made (a CLI flag).
3. A value that is true by construction (format magic bytes, version
   markers, EOF sentinels).

If a format field requires metadata and you didn't provide it, slap
asks or refuses. It does not silently fill in defaults and pretend.

When converting between formats, slap tells you what survives and what
gets dropped. It rejects conversions when required metadata is missing
rather than fabricating it. If you supply the missing metadata via a
flag, the conversion proceeds. The tool is permissive, but explicitly
so.

**What this means in practice:**

- `slap create --format ppf3 orig.gba mod.gba patch.ppf` works.
  Adding `--undo` includes undo data. Adding `--validate` includes a
  validation block. If you don't ask for them, they aren't there.
- `slap convert patch.bps --to ips` works if the patch fits in IPS's
  24-bit offset range. If it doesn't, slap tells you why and suggests
  `--to ips32`.
- `slap convert patch.ppf --to ips` warns you that it's dropping the
  description, undo data, and validation block. Nothing is silently
  lost.
- `slap info patch.rup` shows you exactly what's in the patch,
  including fields that are technically present but zero.

**What slap will not do:**

- Fabricate an author, description, or version string you didn't
  provide.
- Silently drop data during conversion without telling you.
- Pretend a conversion succeeded when it can't preserve required
  fields.
- Create PPF4 patches (reverse-engineered format with no natural
  diff-creation analogue — apply and convert-via-source work fine).

## Supported formats

| Format | Apply | Create | Undo |
|--------|-------|--------|------|
| IPS | yes | yes | - |
| IPS32 | yes | yes | - |
| EBP | yes | yes | - |
| BPS | yes | yes | - |
| UPS | yes | yes | yes |
| PPF1 | yes | - | - |
| PPF2 | yes | - | - |
| PPF3 | yes | yes | yes |
| PPF4 | yes | - | - |
| VCDIFF/xdelta3 | yes | - | - |
| BSDiff/BDF | yes | - | - |
| APS (N64) | yes | yes | - |
| APS (GBA) | yes | yes | - |
| RUP/NINJA2 | yes | yes | - |
| NINJA1 | yes | yes | - |
| GDIFF | yes | yes | - |
| xdelta1 | yes | - | - |
| DPS | yes | yes | - |
| PMSR | yes | yes | - |
| PCHTXT | yes | yes | - |

## Usage

```
# Apply a patch (format auto-detected)
slap apply patch.bps rom.gba

# Apply with explicit output path
slap apply patch.ips rom.sfc -o patched.sfc

# Apply in-place (modifies the file directly, creates .bak backup)
slap apply patch.ups rom.gba --in-place

# Create a patch
slap create --format bps original.gba modified.gba patch.bps

# Create with metadata
slap create --format ebp original.gba modified.gba patch.ebp \
  --title "My Patch" --author "me" --description "v1.0"

# Convert between formats
slap convert patch.bps --to ips32

# Convert a differential format (needs source ROM)
slap convert patch.rup --to bps --with original.gba

# Inspect a patch
slap info patch.ppf

# Detailed record-level view
slap explain patch.ips

# Undo a patch (PPF3 with undo data, or UPS)
slap undo patch.ppf3 patched.gba
```

## Building from source

Requires GHC 9.12.2, cabal-install, and a Rust toolchain (cargo).

```
make           # builds Rust staticlib, then Haskell
make test      # property tests + integration suite
cabal install --extra-lib-dirs=$(pwd)/rusty-slap/target/release
```

## Known limitations

- **PPF4 create:** PPF4 is a reverse-engineered Pyriel-internal format.
  Apply and convert-via-source work. Direct creation is not supported.
- **EBPatcher interop:** slap-created EBP patches embed
  `"patcher":"slap"` in the JSON metadata. EBPatcher.js rejects
  patches from unknown patchers. This is by design — slap identifies
  itself honestly.
- **RUP text encoding round-trip:** the PATCH_ENC byte is parsed and
  displayed but set to 0 (system codepage) on creation. No known
  real-world RUP patch uses a non-zero value.

## Bug reports

If you find a patch that slap handles incorrectly, please report it
with the patch file and the tool you compared against.

## License

MIT
