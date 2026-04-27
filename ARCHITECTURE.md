# Architecture

slap is a Haskell CLI backed by a small Rust staticlib (`rusty-slap`)
for byte-crunching. Haskell owns parsing, applying, creating,
converting, inspecting, and the CLI; Rust owns CRC-32, Adler-32,
SA-IS suffix array, BPS diff, and decompression.

CLAUDE.md describes the values; this document covers the shape. If
the document and the code disagree, trust the code.

## Layering

Four layers, dependencies flowing strictly downward.

1. **Foundation.** No format-specific knowledge: `Measure`,
   `FileContents`, `FFI`, `Binary`, `Get`, `Format`, `Compress`,
   `FormatLabel`, `Checksum`, `Error`, `TextEncoding`, `JSON`,
   `PatchField`, `MetadataField`, `Constraint`, `Platform`,
   `PlatformType`.

2. **Format modules.** Each `Slap/Foo/` directory owns one format,
   decomposed into `Types`, `Parse`, `Apply`, `Describe`, `Create`.
   Additional format-specific modules are allowed where the work
   earns its own home — `Slap.IPS.Optimize` is the current example,
   hosting the DP partitioner that decides which copy and RLE
   records IPS create should emit. Some formats currently lack
   `Create` and some currently return `TargetFileContents` directly
   instead of `Either SlapError TargetFileContents`; both are gaps
   the project is closing, not design choices. No format module
   imports another format module; siblings share only the
   foundation.

3. **Coordination.** `Types`, `Detect`, `Explain`, `Convert`,
   `SomePatch`, `Create`, `Archive`, `Yay0`. Bridges between
   format-specific code and the CLI.

4. **Entry point.** `Main`: CLI via `optparse-applicative`, six
   subcommands (`apply`, `undo`, `create`, `convert`, `info`,
   `explain`).

## The spine: `SomePatch`

`SomePatch` is the one place where format-specific types exist.
Its fields are closures and format-agnostic data: apply and undo
strategies, structured verification, `ExplainData`, warnings, a
format label, and — for direct formats — a `PatchContents` for the
conversion engine. `parseSome` is the only dispatch point;
everything downstream works through closures.

Adding a format is mechanical: a new `Slap/Foo/` directory, a case
in `Detect`, a block in `parseSome`, CLI wiring in `Main`, and —
if direct — `PatchContents` population plus a row in
`directConversionContract`.

## Conversion

The conversion engine's posture is to refuse. Most format pairs cannot be honestly converted, and slap's job is to detect that and say so — naming what's missing, what would be dropped, and (where useful) which targets would work. A successful conversion is what falls out when the contracts happen to align; a refusal is the engine doing what it was designed to do, not a failure to overcome. "Force it" is the wrong instinct. The exhaustive matrices, the per-format acceptance sets, and the affectsApplyOutput distinction all exist so that refusals are precise and load-bearing rather than apologetic.

Direct formats carry literal replacement bytes; differential
formats carry instructions. Source-less conversion (`convert FROM
TO`) only works between direct formats whose contracts agree;
differential targets always need `--with SOURCE` (apply, then
re-create from source and reconstructed target).

`Convert.PatchContents` is the universal direct-patch bag.
`directConversionContract` declares what each direct target
requires and accepts; `canConvert` consults that against a
`PatchContents`. `acceptedMetadataFields` and `acceptedConstraints`
are exhaustive per-format matrices governing CLI flag rejection —
the former for fields embedded in the patch, the latter for opt-in
refuse-gates that change *whether* slap proceeds rather than *what*
it emits. Both are pattern-matched exhaustively, so adding a new
format or a new field/constraint fires `-Wincomplete-patterns`
everywhere a decision is needed.

`Slap.Create` hosts per-format porcelain for differential creation
only. Direct creation goes through `createFromMemory` and routes
through `Convert`'s `PatchContents` pipeline (`buildContents` then
`encodeDirect`); the pipeline is shared, so per-format porcelain
would have nothing format-level to wrap.

## Type-level seams

`Slap.Measure` holds the role newtypes (`Offset`, `Length`,
`FileSize`, `Delta`, `Position`, plus error-context role newtypes)
and the `Cursor` typeclass. `Slap.FileContents` holds
`SourceFileContents`, `TargetFileContents`, `PatchFileContents` so
buffer roles can't be transposed. `Slap.Error` holds `SlapError`
and `SlapWarning` as closed sums with typed fields, plus the
narrower `ApplyError` vocabulary that lifts in via `ApplyFailed` /
`UndoFailed`.

## The format roster

| Module  | Class        | Create                |
|---------|--------------|-----------------------|
| IPS     | Direct       | Yes (IPS, IPS32, EBP) |
| PPF     | Direct       | Yes (v3 only)         |
| NINJA1  | Direct       | Yes                   |
| PMSR    | Direct       | Yes                   |
| PCHTXT  | Direct       | Yes                   |
| APSN64  | Direct       | Yes                   |
| BPS     | Differential | Yes                   |
| UPS     | Differential | Yes                   |
| DPS     | Differential | Yes                   |
| NINJA2  | Differential | Yes                   |
| APSGBA  | Differential | Yes                   |
| GDIFF   | Differential | Yes                   |
| VCDIFF  | Differential | No                    |
| BSDiff  | Differential | No                    |
| XDelta1 | Differential | No                    |

`Slap.IPS.Apply`, `Slap.BPS.Apply`, `Slap.UPS.Apply`,
`Slap.DPS.Apply`, `Slap.VCDIFF.Apply`, `Slap.BSDiff.Apply`, and
`Slap.XDelta1.Apply` return `Either SlapError TargetFileContents`.
The remaining apply functions return `TargetFileContents` directly
and can silently produce wrong output for malformed input. Every
format will eventually be both creatable and strict; today's gaps
are work in progress.

`Slap.BPS`, `Slap.UPS`, `Slap.IPS`, and `app/Main.hs` are the
current polish references.

## rusty-slap

A Rust staticlib, fat LTO, `panic=abort`, linked into the Haskell
binary via FFI. CRC-32 and Adler-32 (via `crc32fast` and a
hand-rolled adler32), SA-IS suffix array, BPS diff, and
decompression for zlib, gzip, and bzip2 (via pure-Rust `flate2` and
`bzip2-rs`, so the staticlib has no C dependencies and Cargo
handles cross-platform builds cleanly).

The FFI boundary lives in `Slap.FFI` (CRC-32, Adler-32, BPS diff)
and `Slap.Compress` (decompression). Rust allocates output buffers;
Haskell copies into `ByteString` and calls `rusty_free`. Adding a
new decompressor — for example, lzma for VCDIFF/xdelta3 secondary
compression — follows the existing pattern: a function in
`compress.rs`, a `pub unsafe extern "C"` wrapper in `lib.rs`, a
`foreign import ccall` and a public function in `Slap.Compress`.
This layer is expected to grow over time.