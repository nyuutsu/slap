# slap — Project Instructions

## What this is

A multi-format ROM patching CLI. Auto-detects format from magic bytes,
applies patches, and can round-trip create several formats. The goal is
one tool that handles everything — IPS, BPS, UPS, PPF, VCDIFF, APS,
RUP, BSDiff, GDIFF, xdelta1 — so you never have to hunt for a
format-specific patcher.

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
Format-specific types stay in their own module — the top-level
`Patch.Types` just holds the `PatchFormat` enum and `SomePatch` union
for dispatch.

`Patch.Binary` holds shared primitives: endian readers, varint codecs,
CRC32, and the `copyBSRange` bulk-copy helper. Anything that two or
more format modules need goes here rather than being duplicated.

`Main.hs` is purely dispatch — parse CLI args, detect format, call the
right module. No format-specific logic lives in Main.

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

No test suite yet. Testing is manual against real patch files —
`TESTING.md` has the per-format checklist. Round-trip tests for
creation formats (IPS, BPS, UPS, PPF3) only need two differing
binary files.
