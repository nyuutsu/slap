# Architecture

slap is a Haskell CLI backed by a small Rust staticlib (`rusty-slap`) for byte-crunching. Haskell owns parsing, applying, creating, converting, inspecting, and the CLI; Rust owns CRC-32, Adler-32, SA-IS suffix array, BPS diff, and decompression.

CLAUDE.md describes the values; this document covers the shape. If the document and the code disagree, trust the code.

## Layering

Four layers, dependencies flowing strictly downward.

1. **Foundation.** No format-specific knowledge: `Measure`, `FileContents`, `FFI`, `Binary`, `ByteParser`, `PatchFormat`, `Compression.Stream`, `FormatLabel`, `Checksum`, `Status`, `Text`, `FieldName`, `JSON`, `PatchField`, `MetadataField`, `MetadataInclusion`, `Constraint`, `Dialect`, `Narrow`, `Platform`, `PlatformType`.

2. **Format modules.** Each `Slap/Foo/` directory owns one format, decomposed into `Types`, `Parse`, `Apply`, `Describe`, `Create`. Additional format-specific modules are allowed where the work earns its own home — `Slap.IPS.Optimize` is the current example, hosting the DP partitioner that decides which copy and RLE records IPS create should emit. Some formats currently lack `Create`; that's a gap the project is closing, not a design choice. No format module imports another format module; siblings share only the foundation.

3. **Coordination.** `Detect`, `Convert`, `SomePatch`, `Create`, `Display`, `Compression.Yay0`. Bridges between format-specific code and the frontend.

4. **Native frontend (`app/`).** `Main` dispatches the six subcommands (`apply`, `undo`, `create`, `convert`, `info`, `explain`) and runs the IO handlers; `CLI` is the `optparse-applicative` command surface; `Archive` / `Archive.Zip` unwrap single-entry archives (ZIP in-process, RAR and 7z by shelling out). This layer links the engine, never the reverse.

## The spine: `SomePatch`

`SomePatch` is the one place where format-specific types exist. Its fields are closures and format-agnostic data: apply and undo strategies, structured verification, the info and analysis data that `info` and `explain` render, advisories, a format label, and a `PatchKind` — either `Differential`, or `Direct` carrying a `Maybe PatchContents` for the conversion engine (`Nothing` when the direct format can't be re-encoded source-lessly, as with PPF4's Append commands). `parseSome` is the only dispatch point; everything downstream works through closures.

Adding a format is mechanical: a new `Slap/Foo/` directory, a case in `Detect`, a block in `parseSome`, CLI wiring in `Main`, and — if direct — `PatchContents` population plus a row in `directConversionContract` and arms in the `acceptedMetadataFields` / `acceptedConstraints` / `acceptedDialects` matrices.

## Conversion

The conversion engine's posture is to refuse. Most format pairs cannot be honestly converted, and slap's job is to detect that and say so — naming what's missing, what would be dropped, and (where useful) which targets would work. A successful conversion is what falls out when the contracts happen to align; a refusal is the engine doing what it was designed to do, not a failure to overcome. "Force it" is the wrong instinct. The exhaustive matrices, the per-format acceptance sets, and the affectsApplyOutput distinction all exist so that refusals are precise and load-bearing rather than apologetic.

Direct formats carry literal replacement bytes; differential formats carry instructions. Source-less conversion (`convert FROM TO`) only works between direct formats whose contracts agree; differential targets always need `--with SOURCE` (apply, then re-create from source and reconstructed target).

`Convert.PatchContents` is the universal direct-patch bag. `directConversionContract` declares what each direct target requires and accepts; `canConvert` consults that against a `PatchContents`. Three exhaustive per-format matrices govern CLI flag rejection: `acceptedMetadataFields` (fields embedded in the patch), `acceptedConstraints` (opt-in refuse-gates that change *whether* slap proceeds rather than *what* it emits), and `acceptedDialects` (wire-interpretation choices the file alone can't disambiguate, so the user picks the reading — PPF1 offset endianness is the current axis). Constraints and dialects are companions: a constraint gates whether slap proceeds, a dialect changes how the bytes are read or written. All three are pattern-matched exhaustively, so adding a new format or a new field/constraint/dialect fires `-Wincomplete-patterns` everywhere a decision is needed.

`Slap.Create` hosts per-format porcelain for differential creation only. Direct creation goes through `createPatch` and routes through `Convert`'s `PatchContents` pipeline (`buildContents` then `encodeDirect`); the pipeline is shared, so per-format porcelain would have nothing format-level to wrap.

## Type-level seams

`Slap.Measure` holds the role newtypes (`Offset`, `Length`, `FileSize`, `Delta`, `Position`), plus error-context role newtypes and the `Cursor` typeclass. `Slap.FileContents` holds `InputFileContents`, `OutputFileContents`, `PatchFileContents` so buffer roles can't be transposed. `Slap.Status` holds `SlapError` and `SlapAdvisory` as closed sums with typed fields, plus the narrower `ApplyError` vocabulary that lifts in via `ApplyFailed` / `UndoFailed`.

## The format roster

| Module  | Class        | Create                 |
|---------|--------------|------------------------|
| IPS     | Direct       | Yes (IPS, IPS32, EBP)  |
| PPF1    | Direct       | Yes                    |
| PPF2    | Direct       | Yes                    |
| PPF3    | Direct       | Yes                    |
| PPF4    | Direct       | Yes                    |
| NINJA1  | Direct       | Yes                    |
| PMSR    | Direct       | Yes                    |
| APSN64  | Direct       | Yes                    |
| BPS     | Differential | Yes                    |
| UPS     | Differential | Yes                    |
| DPS     | Differential | Yes                    |
| NINJA2  | Differential | Yes                    |
| APSGBA  | Differential | Yes                    |
| GDIFF   | Differential | Yes                    |
| VCDIFF  | Differential | Yes (RFC, xdelta3)     |
| BSDiff  | Differential | No                     |
| XDelta1 | Differential | Yes                    |

Appliers return `Either SlapError OutputFileContents`; some wrap the success side in `Outcome` to carry apply-time advisories.

`Slap.BPS`, `Slap.UPS`, `Slap.IPS`, and `app/Main.hs` are the current polish references. `Slap.Display` is part of the way there.

## rusty-slap

A Rust staticlib, fat LTO, `panic=abort`, linked into the Haskell binary via FFI. CRC-32 and Adler-32 (via `crc32fast` and a hand-rolled adler32), SA-IS suffix array, BPS diff, compression and decompression for zlib, gzip, and xdelta3-flavored LZMA, and decompression for bzip2 (via pure-Rust `flate2`, `bzip2-rs`, `lzma-rs`, and — for the LZMA2 encoder `lzma-rs` lacks — `lzma-rust2`, so the staticlib has no C dependencies and Cargo handles cross-platform builds cleanly).

The FFI boundary lives in `Slap.FFI` (CRC-32, Adler-32, BPS diff) and `Slap.Compression.Stream` (compression codecs). Rust allocates output buffers; Haskell copies into `ByteString` and calls `rusty_free`. Adding a new codec follows the existing pattern: a function in `compress.rs` (or its own module when it carries real mechanism, as `xdelta3_lzma.rs` does), a `pub unsafe extern "C"` wrapper in `lib.rs`, a `foreign import ccall` and a public function in `Slap.Compression.Stream`. This layer is expected to grow over time.