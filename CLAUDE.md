# slap — Project Instructions

## What this is

A multi-format ROM patching CLI. Auto-detects format from magic bytes,
applies/undoes patches, creates patches, converts between formats, and
provides info/explain commands for inspection. The goal is one tool
that handles everything — IPS, IPS32, EBP, BPS, UPS, PPF (1/2/3/"4"),
VCDIFF/xdelta3, APS (N64/GBA), RUP/NINJA2, NINJA1, DPS, BSDiff/BDF,
GDIFF, xdelta1, PMSR (with Yay0 decompression) — so you never have
to hunt for a format-specific patcher.

## Code style

GHC2024 language edition. Build with `-Wall -O2`, zero warnings at all
times. If a warning fires, fix the code — don't disable the warning.

Prefer the shorter, cleaner way to express something. Pattern matching
over if-chains, guards over nested cases, `where` over deeply nested
`let`. Reach for standard combinators (`unfoldr`, `foldl'`, `mapAccumL`)
when they fit naturally — don't write manual recursion to avoid learning
a combinator, but don't force one in when direct recursion reads better.

Terse variable names in tight scope — `bs` for a ByteString, `pos` for
an offset, `acc` for an accumulator. Descriptive names for things that
cross function boundaries or appear in record fields.

`fromIntegral` is unavoidable in binary format code. Don't try to hide
it — explicit type conversions at byte boundaries are clearer than type
class abstractions.

## Comments

Comments explain *why*, not *what*. If a comment restates the code next
to it, delete the comment. `-- increment counter` is noise. `-- bit 0
encodes sign, bits 1+ encode magnitude` is signal.

Format spec references are welcome — a comment explaining which RFC
section or which bytes in a header correspond to what saves the next
reader a trip to the spec. Wire format details are not obvious from code.

No `-- TODO` comments in committed code. Either do it or track it
outside the source.

## Architecture

Each patch format gets its own module under `Patch/`. Every format
module exports at minimum `parse` and `apply`; most also export `info`.
Format-specific types stay in their own module — `Patch.Types` holds
only the `PatchFormat` enum for detection.

`SomePatch` is a **closure-based existential** — a record of closures
defined in `Main.hs`, not a sum type. `parseSome` is the single
dispatch point: it parses raw bytes into format-specific types, then
closes over them to produce a `SomePatch` carrying `spInfo`, `spExplain`,
`spApply`, `spUndo`, `spDirectConvert`, etc. All consumers work through
these fields. Adding format #12 means adding one block to `parseSome`;
nothing else changes.

Shared infrastructure:

- `Patch.Archive` — ZIP/RAR/7z detection (magic bytes) and single-entry
  extraction via external tools (`unzip`, `unrar`, `7z`). Filters chaff
  (readmes, images, docs) to find the sole patch candidate.
- `Patch.Binary` — Endian readers, varint codecs (byuu, VCDIFF, EDSIO),
  CRC32, builder helpers (`putWord16BE`, `putWord32LE`, `putByuuVarint`),
  and `copyBSRange` for bulk memcpy into output buffers.
- `Patch.Get` — Pure position-threading parser monad over strict
  ByteString. All format parsers use this instead of raw index arithmetic.
- `Patch.Detect` — Magic-byte detection, returns `PatchFormat` enum.
  APS is the tricky one: "APS N64" and "APS GBA" are two unrelated
  formats by different authors who both chose the name "APS." N64 magic
  is the 5 ASCII bytes `APS10`; GBA magic is the 4 bytes `APS1` followed
  by a LE u32 source size — so byte 5 is data, not magic.  The `0` in
  `APS10` is ASCII 0x30, not a null byte; a collision occurs when the
  source size's low byte is 0x30 (trimmed/hacked ROMs can hit this).
  Without disambiguation, the N64 parser silently eats GBA data as
  variable-length records and applies garbage writes — no checksums,
  no diagnostic.  `parseAPS` disambiguates by checking GBA's rigid file
  structure (12 + N×65544 bytes, each record offset 64KB-aligned).
  Note: "N64 format" vs "GBA format" refers to the spec variant, not
  the target platform — N64-format patches are commonly used for GBA
  games.
- `Patch.Explain` — Record-by-record textual dumps for all formats.
- `Patch.Format` — Shared display helpers (CRC formatting, hex padding,
  hex dumps, number alignment).

`Patch.Yay0` — Nintendo LZSS decompression for Star Rod `.mod` files.
Yay0-compressed PMSR is transparently decompressed in `parseSome`;
info/explain output shows "PMSR/Yay0" to distinguish from raw PMSR.

`Main.hs` is CLI parsing (optparse-applicative), `parseSome` dispatch,
and uniform command handlers. Commands: apply, undo, create, convert,
info, explain. Apply is safe by default (writes to derived output name,
source file untouched); `--in-place` / `-i` opts into destructive mode
with automatic `.bak` backup. Apply handles two strategies (`InPlace`
for file-handle formats, `InMemory` for delta formats) through a
single code path.

Archive unwrapping is transparent: patch files are always unwrapped
(ZIP/RAR/7z → inner patch); source/ROM files respect `--raw` to skip
unwrapping. `readUnwrap` and `readMaybeUnwrap` handle this in Main.hs.

`SomePatch` carries `spWarnings :: [String]` for health diagnostics
(missing EOF markers, empty patches). All command handlers emit these
to stderr via `emitWarnings`.

## Performance

Use `unsafeCreate` from `Data.ByteString.Internal` for building output
buffers in apply functions. For copying from a ByteString into a raw
pointer, use `copyBSRange` (which wraps memcpy) — not byte-by-byte
`mapM_`/`pokeByteOff` loops. The one exception is BPS TargetCopy, where
the source and destination regions overlap and byte-by-byte is
semantically required.

## Error handling

`Either String` for parse/apply errors. A proper error ADT would be
over-engineering for a CLI tool where every error path ends in
`hPutStrLn stderr` and `exitFailure`. The PPF module has a `ParseError`
ADT from the early days; that's fine, but don't feel obligated to
replicate it in every format.

## Testing

Three test harnesses, 212 tests total:

**`test/run.sh`** — Apply tests (91 tests). Each `.suite` file in
`test/suites/` is a declarative manifest: header (base ROM path,
expected SHA256) followed by pipe-delimited patch lines with format
name, patch path, confidence level (gold/verified/untested/broken),
and provenance. Applies each patch to the base ROM, checks SHA256.

**`test/roundtrip.sh`** — Round-trip tests (66 tests). Validates
create, undo, convert, info, and explain. Bootstraps target files
from existing BPS patches, then round-trips through all create
formats. Tests UPS self-inverse undo, PPF3 undo-with-create,
IPS↔IPS32 direct conversion, and info/explain smoke tests including
PMSR/Yay0 `.mod` files.

**`test/flags.sh`** — Flag and error path tests (55 tests). Covers
corrupt/invalid input, `--dry-run`, `--force`/CRC mismatch,
`--in-place`/`--no-backup`, output collision, `--verbose`, undo
error paths, convert error paths, compound flag combinations,
PPF3 `--undo --validate`, hidden aliases (`--yolo`, `--send-it`,
`--clobber`), patch health warnings, empty diffs (identical files),
undo with `-o` redirect, automated archive unwrapping (ZIP),
convert with `--with` (apply-and-recreate path), and IPS truncation
markers.

Test data lives in `test/data/` — one directory per game, base ROM
named `base.{ext}`, patches with clean names. Current coverage:

- **dm4k** — 14 formats, light diff (4 MB GBC)
- **emerald** — 3 scenarios (heavy-diff, RLE, size-change) across 13 formats each (16 MB GBA)
- **stadium2** — 3 scenarios across 11 formats each (64 MB N64)
- **tetris** — BDF + UPS cross-validation (real-world, 32 KB GB)
- **paper-mario** — APS-N64 + IPS cross-val, 2 PMSR/Yay0 Star Rod `.mod` files
- **11 more real-world suites** — Banjo-Tooie (APS-N64), FFTA (APS-GBA), Kirby DL2 (BPS), Mother 3 (UPS stress), SotN (PPF3), Suikoden (5 PPF4 bugfixes), FE6 (IPS stress)

Run all: `cabal build && bash test/run.sh && bash test/roundtrip.sh && bash test/flags.sh`
Filter: `bash test/run.sh "" dm4k`

Base ROMs are gitignored; test patches are committed.
