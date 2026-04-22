# Architecture

slap is a Haskell CLI backed by a small Rust staticlib (`rusty-slap`)
for byte-crunching primitives. Haskell owns parsing, applying,
creating, converting, inspecting, and the CLI. Rust owns the things
that would be slow in Haskell: CRC-32, Adler-32, suffix-array
construction, BPS diff, compression.

The CLAUDE.md files describe the values the code is held to — type-
level correctness, aggressive use of newtypes, long and descriptive
names. This document covers the *shape* of the codebase; the values
and the shape reinforce each other. If anything here contradicts what
the code actually does, trust the code.

## Layering

Four layers, dependencies flowing strictly downward:

1. **Foundation.** Modules under `Slap/` with no format-specific
   knowledge: `Measure`, `FileContents`, `FFI`, `Binary`, `Get`,
   `Format`, `Compress`, `FormatLabel`, `Checksum`, `Error`,
   `TextEncoding`, `PatchField`, `Platform`. These define the
   vocabulary everything above is written in.
2. **Format modules.** Each `Slap/Foo/` directory owns one patch
   format. The decomposition is always:
   ```
   Foo/Types.hs    — parsed representation
   Foo/Parse.hs    — bytes → Either SlapError FooPatch
   Foo/Apply.hs    — patch + source → target
   Foo/Describe.hs — patch → ExplainData
   Foo/Create.hs   — (optional) source + target → patch bytes
   ```
   No format module imports another format module; they are
   siblings that share only the foundation.
3. **Coordination.** `Types`, `Detect`, `Explain`, `Convert`,
   `SomePatch`, `Archive`, `Yay0`. Bridges between format-specific
   code and the CLI.
4. **Entry point.** `Main`: CLI via `optparse-applicative`, six
   subcommands (`apply`, `undo`, `create`, `convert`, `info`,
   `explain`).

## The spine: `SomePatch`

`SomePatch` is the one place where format-specific types exist.
Its record fields are closures and format-agnostic data: apply and
undo strategies over `SourceFileContents` / `TargetFileContents`,
structured verification data (hashes, block CRCs, Adler32 windows),
`ExplainData` for rendering, structured warnings, a format label,
and — for direct formats only — a `PatchContents` for the
conversion engine.

`parseSome` is the only dispatch point. Every downstream consumer
works through those closures and never sees a format-specific type.

Adding a format is mechanical: a new `Slap/Foo/` directory following
the standard decomposition, a case in `Detect`, a block in
`parseSome`, CLI wiring in `Main`, and — if it's a direct format —
`PatchContents` population plus a `FormatSpecification` in `Convert`.
The contract system handles everything else.

## Direct vs differential

"Direct" formats carry literal replacement bytes at offsets — the
source is needed for verification, not reconstruction. "Differential"
formats carry instructions that transform source into target, and
the source is structurally required.

This distinction is what makes conversion tractable: any direct
patch can, in principle, be expressed in any other direct format
whose `FormatSpecification` accepts the fields in the source's
`PatchContents`. Differential-to-anything conversion generally can't
be done without the source file in hand.

## Conversion

`Convert.PatchContents` is the universal bag of direct-patch data:
records, optional hashes, validation blocks, undo data, truncation
markers, EBP metadata, ROM/image type, text encoding.
`FormatSpecification` declares what each target format requires and
accepts. `canConvert` and `conversionNotes` check the contract;
`convertDirect` encodes a `PatchContents` into a target.

There are two paths through `convert`, and they have very different
semantics:

- **Source-less** (`convert FROM TO`). Works only when the source
  format's `PatchContents` carries enough to satisfy the target
  format's spec. Differential formats can't participate at all —
  they have no `PatchContents` to hand over. Many direct-to-direct
  pairs are also impossible: the target's encoding range might
  exclude the records, or require hashes the source didn't carry.
  The contract system says no honestly and reports dropped fields as
  structured `SlapWarning` values. Do not treat coverage of this
  path as a goal; treat its "no" as a feature.

- **With a source file** (`convert FROM TO --with SOURCE`). Mostly
  sugar over "apply the source patch to reconstruct the target,
  then create a fresh patch in the target format from source and
  reconstructed target." This makes nearly every pair tractable.
  Main.hs takes this path unconditionally when `--with` is present,
  calling `applyForConvert` and then `createFromMemory`. The
  remaining ~5% that isn't pure sugar is metadata routing: carrying
  descriptions, ROM type, undo/validation preferences, and similar
  fields across formats that don't all express them the same way.
  `createFromMemory` takes the parsed source patch's `PatchContents`
  as an optional metadata donor for exactly this reason.

`Convert`'s sibling in the coordination layer is `Create`: the single
home for "the thing that makes a patch", exposing one named entry
point per format slap can emit. The differential porcelain there
forwards directly to each format's `Slap/Foo/Create.createFoo`; the
direct porcelain is a thin layer over `createFromMemory`, since
direct-format creation is a `PatchContents` pipeline that `Convert`
owns. Callers that arrive with a `CreateFormat` tag (the CLI) still
use `createFromMemory`; callers whose target is fixed statically use
the per-format porcelain in `Create`.

## Types that do the work

Three type design choices shape everything else:

- **Measure newtypes.** `Offset`, `Length`, `FileSize`, `Delta`,
  `Position` prevent mixing byte offsets with byte lengths. Layered
  on top, role newtypes (`ReadOffset` vs `WritePosition`,
  `RequestedLength` vs `RemainingLength`, `ActualSize` vs
  `ExpectedSize`, and so on) are used wherever an error variant or
  record field would otherwise have two arguments of the same base
  type — the role is then visible at construction, pattern-match,
  and rendering sites without needing to consult documentation. A
  `Cursor` typeclass abstracts position arithmetic over `Offset`
  and `SignedOffset`.

- **FileContents newtypes.** `SourceFileContents`,
  `TargetFileContents`, `PatchFileContents` are thin wrappers around
  `ByteString` that mark the role each buffer plays in the patch
  lifecycle. The apply layer consumes `SourceFileContents` and
  produces `TargetFileContents`; the parse layer consumes
  `PatchFileContents`. A caller can't pass a ROM where a patch is
  expected, or vice versa.

- **Structured errors and warnings.** `SlapError` and `SlapWarning`
  are closed sums whose constructors carry typed fields, not
  strings. Apply-time errors live in their own type (`ApplyError`)
  and lift into `SlapError` via `ApplyFailed` / `UndoFailed`, so the
  apply layer can be written against a narrower vocabulary.
  Renderers (`renderSlapError`, `renderSlapWarning`,
  `renderApplyError`) are the only code that turns these values
  into strings — everything else holds them structurally.

## The format roster

| Module  | Classification | Create |
|---------|----------------|--------|
| IPS     | Direct         | Yes (IPS, IPS32, EBP) |
| PPF     | Direct         | Yes (v3 only) |
| NINJA1  | Direct         | Yes |
| PMSR    | Direct         | Yes |
| PCHTXT  | Direct         | Yes |
| APSN64  | Direct         | Yes |
| BPS     | Differential   | Yes |
| UPS     | Differential   | Yes |
| DPS     | Differential   | Yes |
| NINJA2  | Differential   | Yes |
| APSGBA  | Differential   | Yes |
| GDIFF   | Differential   | Yes |
| VCDIFF  | Differential   | No |
| BSDiff  | Differential   | No |
| XDelta1 | Differential   | No |

Most apply functions return `Either SlapError TargetFileContents`
and validate strictly. DPS and GDIFF are still permissive — they
return `TargetFileContents` directly and can silently produce wrong
output for malformed input.

The spine — `SomePatch` dispatch, the conversion engine, the
foundation-layer types — is in a state the project is happy with.
Among the format modules, BPS and UPS have had their individual
polish passes and are the current reference implementations; the
others are in varying intermediate states awaiting theirs.

## rusty-slap

A static library compiled with fat LTO and `panic=abort`, linked
into the Haskell binary via FFI. Its purpose is byte crunching:
CRC-32, Adler-32, SA-IS suffix array, BPS diff, and (de)compression
for zlib/gzip/bzip2. The FFI boundary lives in `Slap.FFI` and
`Slap.Compress`: Rust allocates output buffers; Haskell copies them
into `ByteString` and calls `rusty_free`. This split is expected to
absorb more byte-level work over time.
