# slap — Project Instructions

## What this is

A multi-format ROM patching CLI. Auto-detects format from magic bytes,
applies/undoes patches, creates patches, converts between formats, and
provides info/explain commands for inspection.

## Build and test

```
cabal build    # GHC 9.12.2, GHC2024, -Wall -O2, zero warnings
cabal test     # props (QuickCheck) + integration (tasty)
```

Filter: `cabal test integration --test-options='-p "$0~/apply/"'`

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

## Error handling

`Either String` for parse/apply errors. A proper error ADT would be
over-engineering for a CLI tool where every error path ends in
`hPutStrLn stderr` and `exitFailure`.

Error message convention:
- Format prefix: `"FORMAT: description"` (e.g., `"BPS: input too short"`)
- Magic checks: `"not a FORMAT file (bad magic)"`
- Show actual values when rejecting (`"version byte: 7"` not just
  `"bad version"`)

## Performance

Use `unsafeCreate` from `Data.ByteString.Internal` for building output
buffers in apply functions. For copying from a ByteString into a raw
pointer, use `copyBSRange` (which wraps memcpy) — not byte-by-byte
`mapM_`/`pokeByteOff` loops. The one exception is BPS TargetCopy, where
the source and destination regions overlap and byte-by-byte is
semantically required.

## Honesty

Every byte slap writes must come from one of three sources:
1. The inputs (source file, target file, parsed patch).
2. An explicit user choice (CLI flag).
3. A value that is true by construction — format magic bytes, version
   markers, EOF sentinels, and tool identity (e.g. `"patcher":"slap"`).

If a format field requires content metadata and we don't have it: ask
the user or refuse the operation. Never silently invent data.

This means:
- No hardcoded content metadata. If `createFoo` needs an author
  field, it takes a parameter. If the user didn't pass `--author`,
  the field is empty or the operation is rejected — not filled with
  a default.
- Constrained fields use sum types, not raw bytes. If a field can
  only be Append or Truncate, its type is `data OverflowMode =
  OverflowAppend | OverflowTruncate`, not `Word8`. The compiler
  enforces that nobody fabricates a value.
- Conversion preserves what it can and warns about what it drops.
  The contract system in `Patch.Convert` rejects conversions when
  required metadata is missing. `conversionNotes` reports fields
  that don't survive the conversion. Nothing is silently lost.
- Permissiveness is a feature, not a defect — but it must be
  explicit. If a user supplies a missing field via a flag and that
  gets a conversion over the line, good. If the program quietly
  fills in a zero and pretends, bad.

This principle is aspirational — the codebase still has fabricated
values being cleaned up (see NEXT.md prompts 25-26). But every new
code path must follow it, and every existing violation is a bug to fix.

Every committed test patch is either `gold` (real-world) or `verified`
(created by a named external tool). slap never creates its own test
inputs.

## Where to find things

- `src/Patch/` — one module per format (parse, apply, info, explain)
- `src/Patch/SomePatch.hs` — `parseSome` dispatch, `SomePatch` type
- `src/Patch/Convert.hs` — conversion contracts and encoding
- `app/Main.hs` — CLI parsing and command handlers
- `test/` — Props.hs (QuickCheck), Integration/ (tasty integration)
- `NEXT.md` — planned work and session prompts
