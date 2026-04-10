# Architecture

slap is a Haskell CLI with a Rust static library (`rusty-slap`) for performance-critical primitives. The Haskell code handles all parsing, application, creation, conversion, inspection, and CLI logic. The Rust code provides CRC-32, Adler-32, suffix-array construction, BPS diffing, and zlib/gzip/bzip2 compression via C FFI.

## Layers

The codebase has four distinct layers. Dependencies flow strictly downward.

### Foundation

Modules with no format-specific knowledge. Everything above depends on these.

- **`Measure`** — Newtypes (`Offset`, `Length`, `FileSize`, `Delta`, `Position`) that prevent mixing byte offsets, lengths, and sizes. Also defines `Hunk` (offset + payload), `UndoHunk`, `EncodedHunk`, and `EncodingLimits` (whose `formatLabel` field is `FormatLabel`, not `String`). The `Hunk` type is the universal currency for patch records across all direct formats.

- **`FFI`** — Raw C FFI bindings to rusty-slap: `rustyCRC32`, `rustyAdler32`, `rustyBpsDiff`. Handles buffer allocation/deallocation across the language boundary.

- **`Binary`** — Endian readers (`getWord16LE`, `getWord32BE`, etc.), varint decoders (byuu-style for BPS/UPS, VCDIFF-style per RFC 3284), CRC-16/IBM, Adler-32 re-export, cryptographic hashes (MD5 → `MD5Hash`, SHA1 → `SHA1Hash`, SHA256 via cryptohash), `diffHunks` (contiguous-diff finder with gap merging), and `Builder` encoders.

- **`Get`** — Position-threading parser monad over `ByteString`. Hand-rolled `StateT Position (Either String)` without monad transformer overhead. Bridges to `Binary` readers via `liftRead` and `liftReadVarint`. Every format parser runs in this monad.

- **`Format`** — Display utilities: hex formatting, field rendering, hex dumps. No business logic.

- **`Compress`** — Zlib inflate/deflate, gzip inflate, bzip2 decompress. Thin wrappers around rusty-slap FFI calls with error handling and buffer management.

- **`FormatLabel`** — Sum type with one constructor per supported format (20 values). Used in error messages, warnings, and `EncodingLimits`. `formatLabelName` renders to a human-facing string.

- **`Checksum`** — Newtypes: `CRC32`, `CRC16`, `Adler32`, `MD5Hash`, `SHA1Hash`. Rendering functions (`showCRC32`, `showAdler32`). Every hash and checksum in the project is a distinct type.

- **`Error`** — `SlapError` (24 constructors covering parse, apply, create, and convert errors), `SlapWarning` (18 constructors for dropped fields, assumed defaults, encoding gaps, truncation), `FieldName` (metadata field identity for error context), `CreateResult` (patch bytes + warnings from creation). Renderers: `renderSlapError`, `renderSlapWarning`.

- **`TextEncoding`** — Locale and UTF-8 encoding/decoding for metadata text fields. `encodeBoundedLocale`/`encodeBoundedUtf8` for creation (encode, truncate at codepoint boundary, null-pad). `decodeLocaleField`/`decodeUtf8Field` for display. `isValidUtf8` for opaque-to-flagged conversion heuristic.

- **`PatchField`** — Field identity type for the conversion contract system. Extracted from Convert to break an import cycle with Error. `fieldName` renders to a human string.

### Format modules

Fifteen format families, each in its own `Slap/Foo/` directory. Every format follows the same decomposition:

```
Foo/Types.hs    — data types for the parsed patch
Foo/Parse.hs    — ByteString → Either SlapError FooPatch
Foo/Apply.hs    — FooPatch → source ByteString → target ByteString
Foo/Describe.hs — FooPatch → [MetaField] + ExplainData
Foo/Create.hs   — (optional) → CreateResult (patch bytes + [SlapWarning])
```

Most apply functions return `Either SlapError ByteString` and validate inputs strictly. Two formats are still permissive (return `ByteString` directly, silently producing wrong output for malformed input): DPS and GDIFF. The strict-apply campaign for those formats is upcoming.

No format module imports another format module. They are fully isolated siblings. Each depends only on the foundation layer.

The formats:

| Module   | Classification | Has Create | Notes |
|----------|---------------|------------|-------|
| IPS      | Direct        | Yes        | IPS, IPS32, and EBP (JSON metadata variant) |
| PPF      | Direct        | Yes        | Versions 1, 2, 3; undo data and validation blocks |
| NINJA1   | Direct        | Yes        | Binary/text subformats, optional zlib compression |
| PMSR     | Direct        | Yes        | Paper Mario Star Rod; big-endian |
| PCHTXT   | Direct        | Yes        | Text-based; block structure with enable/disable |
| APSN64   | Direct        | Yes        | N64 cart ID/country/CRC advisory checks |
| BPS      | Differential  | Yes        | Suffix-array diff via rusty-slap |
| UPS      | Differential  | Yes        | XOR-based, self-inverse |
| DPS      | Differential  | Yes        | Copy + data records with metadata header |
| RUP      | Differential  | Yes        | NINJA2 format; XOR delta blocks |
| APSGBA   | Differential  | Yes        | 64KB-aligned XOR blocks with per-block CRC-16 |
| GDIFF    | Differential  | Yes        | W3C format (RFC NOTE-GDIFF-19970901) |
| VCDIFF   | Differential  | No         | RFC 3284; includes xdelta3 variant |
| BSDiff   | Differential  | No         | BSDIFF40; bzip2-compressed blocks |
| XDelta1  | Differential  | No         | v1.0.4/v1.1; EDSIO varint, gzip compression |

"Direct" means the patch carries literal replacement bytes — the source file is only needed for verification, not reconstruction. "Differential" means the source file is required to produce the target.

### Coordination

Modules that bridge between format-specific code and the CLI.

- **`Types`** — Format taxonomy: `DirectFormat` (6 values), `DiffFormat` (9 values), `PatchFormat` (sum). Used by Detect and SomePatch.

- **`Detect`** — Format identification from raw bytes. Most formats use magic bytes. DPS uses a tentative record walk: checks version byte = 1 and stability flag ∈ {0,1}, then walks the record structure verifying mode bytes and data lengths consume the file exactly. Named constants for all field widths and mode bytes. PCHTXT scans until the first non-comment non-blank line against a data-driven directive list (`@nsobid`, `@flag`, `@enabled`, `@disabled`).

- **`Explain`** — Types and renderers for patch structure visualization. `ExplainData` carries format name, header key-value pairs, sections (regions, blocks, labeled pairs, text), a summary, and notes. The renderer produces sparkline visualizations, region breakdowns, and record-size distributions. Every format's `Describe` module produces `ExplainData`; the renderer is format-agnostic.

- **`Convert`** — The format conversion engine. `PatchContents` is the universal representation of a direct patch's extractable data (records, checksums, hashes, descriptions, undo data, validation blocks, truncation markers, ROM type, etc.). `FormatSpecification` declares what each target format requires and accepts. `canConvert` checks the contract. `conversionNotes` reports dropped fields. `encodeDirect` encodes `PatchContents` to the target format. `createFromMemory` builds patches from source+target bytes. `buildContents` computes `PatchContents` from source and target for direct format creation. Returns `Either SlapError CreateResult`. Warnings are `[SlapWarning]` constructors (not strings). `contentsPatchEncoding` tracks text encoding for encoding-aware conversion. `PatchField` lives in its own module (extracted to break an import cycle with Error).

- **`SomePatch`** — The existential dispatch module. `parseSome` is the single point where format-specific types exist. It takes raw bytes, detects the format, parses it, and returns a `SomePatch` — a record containing closures (`ApplyStrategy`, `UndoStrategy`), verification data, structured warnings (`[SlapWarning]`), explain data (`ExplainData`), record summary (`RecordSummary`), format identity (`FormatLabel`), and optionally `PatchContents` for conversion. No pre-rendered strings — rendering happens at the display boundary. Every consumer works through `SomePatch` fields. No format-specific type escapes this module.

- **`Archive`** — Transparent unwrapping of ZIP, RAR, and 7z archives. Detects by magic bytes, lists entries via shell tools (`unzip`, `unrar`, `7z`), filters out chaff (readmes, images, docs), extracts a sole candidate. Falls back to `7z` when `unrar` isn't available.

- **`Yay0`** — Nintendo LZSS decompression. Yay0 is a compression container, not a patch format. `parseSome` checks for Yay0 magic, decompresses, and recurses.

### Entry point

- **`Main`** — CLI via `optparse-applicative`. Six subcommands: `apply`, `undo`, `create`, `convert`, `info`, `explain`. The `Command` ADT captures all flags and arguments. Handler functions (`doApply`, `doCreate`, etc.) are straightforward: read files, parse patches via `parseSome`, verify, apply/create/convert, write output.

## Key type relationships

```
Main.Command
  → parseSome (raw bytes)
    → detectFormat (magic/heuristic)
    → format-specific Parse
    → SomePatch (closures + data)
      → patchApply    : ApplyStrategy (ByteString → IO (Either SlapError ByteString))
      → patchUndo     : Maybe UndoStrategy
      → patchVerification : Verification (CRC32, MD5, SHA1, blocks, Adler32, etc.)
      → patchExplain  : ExplainData (for rendering)
      → patchWarnings : [SlapWarning]
      → patchFormat   : FormatLabel
      → patchRecordSummary : RecordSummary
      → patchContents : Maybe PatchContents (for direct conversion)

PatchContents
  → canConvert (check FormatSpecification)
  → encodeDirect (to target format CreateResult)
  or
  → createFromMemory (source + target → CreateResult)
```

## Rust (rusty-slap)

A static library compiled with fat LTO and `panic=abort`. Five capabilities:

1. **CRC-32** (`crc32.rs`) — `crc32fast` with hardware acceleration. Called on every apply/create/verify.

2. **Adler-32** (`lib.rs`) — Inline implementation per RFC 1950. Used for VCDIFF window verification.

3. **Suffix array** (`sa.rs`) — SA-IS (Nong, Zhang, Chan 2009), linear time. Used internally by the BPS diff engine.

4. **BPS diff** (`bps_diff.rs`) — Suffix-array matching after Alcaro's Flips. Progressive window sorting: starts with a small window and grows it as the scan advances, re-sorting each time. Returns the raw byuu-varint-encoded action stream.

5. **Compression** (`compress.rs`) — Zlib inflate/deflate via `flate2`, gzip inflate via `flate2`, bzip2 decompress via `bzip2-rs`. Used by NINJA1, xdelta1, BSDiff, VCDIFF, and NINJA1 creation.

The FFI boundary follows a simple pattern: Rust allocates output buffers, Haskell copies them to `ByteString` and calls `rusty_free`. The Haskell side wraps pure Rust functions in `unsafeDupablePerformIO`.

## Encoding limits and sentinel avoidance

IPS, IPS32, and EBP have constrained offset ranges and sentinel values (the EOF marker bytes, when interpreted as an offset, would terminate the record stream early). `EncodingLimits` in `Measure` carries these constraints. Two different strategies apply depending on context:

- **Create path** (source bytes available): `avoidSentinel` in `IPS/Create` shifts a hunk at the sentinel offset back by one byte, prepending the source byte. The narrowing step only validates offset ranges (sentinel stripped from limits).

- **Convert path** (no source bytes): Full limits including sentinel are applied. A hunk at the sentinel offset produces an error because there's no source byte to prepend.

## APS-N64 / APS-GBA disambiguation

Two unrelated formats by different authors both used "APS" as the name. `detectFormat` dispatches on magic bytes: "APS10" → N64, "APS1" → GBA. But "APS10" (N64) collides with "APS1" + a source-size field when `size mod 256 == 48`. `SomePatch.parseSome` refines the detection via `apsGbaStructure`, which checks for GBA's fixed record structure (12 + N × 65544 bytes, 64KB-aligned offsets).
