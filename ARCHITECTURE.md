# Architecture

6,200 lines of Haskell. 26 modules. 16 patch formats. One binary.

## Module Map

```
src/
  Main.hs                 1229 lines   CLI, closure-based dispatch, overlay conversion
  Patch/
    Types.hs                 5 lines   PatchFormat enum
    Detect.hs               31 lines   Magic-byte detection → PatchFormat
    Binary.hs              263 lines   Shared primitives: endian readers, varints, CRC32, memcpy
    Get.hs                 180 lines   Pure parser monad (position-threading over strict ByteString)
    Format.hs               61 lines   Display helpers: hex padding, CRC formatting, hex dumps
    Explain.hs             422 lines   Record-by-record textual dumps for all formats
    Archive.hs             195 lines   ZIP/RAR/7z detection + single-entry extraction
    IPS.hs                 344 lines   IPS + IPS32 + EBP: parse, apply, create, info
    BPS.hs                 231 lines   BPS: parse, apply (unsafeCreate + memcpy), create, info
    UPS.hs                 200 lines   UPS: parse, apply (packZipWith xor), create, info
    VCDIFF.hs              501 lines   VCDIFF/xdelta3: parse, apply (unsafeCreate), info
    BSDiff.hs              139 lines   BSDiff/BDF: parse, apply + external bspatch fallback, info
    GDIFF.hs               211 lines   W3C GDIFF: parse, apply (unsafeCreate), create, info
    XDelta1.hs             214 lines   xdelta v1.1: parse, gzip decompress, apply (unsafeCreate), info
    APS.hs                 330 lines   APS N64 (type 0+1) + GBA: parse, apply, create, info
    RUP.hs                 290 lines   RUP/NINJA2: parse, apply, create, info
    DPS.hs                 233 lines   DPS: parse, apply, create, info
    NINJA1.hs              327 lines   NINJA1 (B/BZ/T/TZ): parse, apply, create, info
    PMSR.hs                176 lines   Paper Mario Star Rod: parse, apply, create, info
    Yay0.hs                107 lines   Nintendo LZSS decompression for Star Rod .mod files
    PPF/
      Types.hs              66 lines   PPF types (Patch, Record, Version, ParseError)
      Parse.hs             166 lines   PPF 1/2/3/4 parser
      Apply.hs              68 lines   PPF apply + undo
      Create.hs            118 lines   PPF3 create (IO wrapper + pure core)
      Info.hs               66 lines   PPF info display
```

## Data Flow

```
                          ┌─────────────┐
  file bytes ──→ Detect ──→ PatchFormat ──→ parseSome ──→ SomePatch
                                                              │
                        ┌─────────┬────────┬────────┬────────┬───────────┘
                        ▼         ▼        ▼        ▼        ▼
                     spInfo   spExplain  spApply  spUndo  spDirectConvert
                    (String)  (String)  (Strategy) (Maybe)  (Maybe OverlaySource)
```

`parseSome` is the **only** function that knows about format-specific
types. It parses the raw bytes, then closes over the parsed data to
produce a `SomePatch` — a record of closures carrying all operations.
Every consumer (`doApply`, `doInfo`, `doConvert`, etc.) works through
`SomePatch` fields, never inspecting the underlying format. Adding
format #17 means adding one block to `parseSome`. Nothing else changes.

## SomePatch — Closure-Based Existential

```haskell
data SomePatch = SomePatch
  { spFormat         :: String
  , spInfo           :: String
  , spExplain        :: String
  , spIsDifferential :: Bool
  , spApply          :: ApplyStrategy
  , spUndo           :: Maybe UndoStrategy
  , spVerboseLines   :: [String]
  , spWarnings       :: [String]
  , spRecordCount    :: Int
  , spRecordUnit     :: String
  , spDirectConvert  :: Maybe OverlaySource
  }

data ApplyStrategy
  = InPlace (FilePath -> IO ())
  | InMemory (BS.ByteString -> IO (Either String BS.ByteString))
             (Maybe Word32)   -- source CRC
             (Maybe Word32)   -- target CRC

data UndoStrategy
  = UndoInPlace (FilePath -> IO (Either String Int))
  | UndoInMemory (BS.ByteString -> BS.ByteString)
```

This is what a typeclass + existential compiles to, but without the
language extensions, module layering constraints, or indirection. The
parsed format-specific data is captured in closures at construction
time. The key tradeoff: you lose the ability to pattern-match on
`SomeIPS` vs `SomeBPS`, but nothing outside `parseSome` needs to.

Apply functions split into two strategies:

1. **InMemory** (BPS, UPS, VCDIFF, BSDiff, GDIFF, XDelta1, DPS):
   Takes source ByteString, returns target ByteString.
   Uses `unsafeCreate` + raw pointer writes for output buffers.

2. **InPlace** (IPS, PPF, APS, RUP, NINJA1, PMSR):
   Seeks and writes into a mutable file. Used for formats that
   were designed for in-place patching.

## Key Design Decisions

**Closure-based existential, not sum type or typeclass.** The original
`SomePatch` was a sum type with 11 constructors, requiring 8 dispatch
functions (someInfo, someExplain, someApply, applyToMemory, tryDirect,
someFmtName, someIsDifferential, needWithMsg) — each with an arm for
every format. That's ~88 case arms, all doing structurally similar
things. A typeclass + existential wrapper would solve the dispatch
problem but adds language extensions, careful module layering, and
indirection. The closure-based record is the same thing typeclasses
compile to, without the ceremony. `parseSome` constructs the record;
consumers use field accessors.

**Patch.Get monad, not attoparsec/binary/cereal.** The parser monad
is 176 lines and provides exactly what binary format parsing needs:
position tracking, bounded reads, error messages with byte offsets.
No dependencies. Parsec-family combinators are for text grammars;
attoparsec is for streaming. Neither fits strict-ByteString binary
formats where you need `getWord32LE` at a specific offset.

**Builder for output, unsafeCreate for apply.** Patch creation uses
`Data.ByteString.Builder` (lazy construction, efficient concat).
Patch application uses `unsafeCreate` with raw pointer arithmetic
(single allocation, memcpy-speed bulk copies via `copyBSRange`).
The distinction matters: creation builds output incrementally from
diffs, while application reconstructs a known-size target buffer.

**Either String for errors.** Every error path ends in `hPutStrLn
stderr` and `exitFailure`. A structured error ADT would add type
safety that no consumer benefits from. The PPF module has a
`ParseError` ADT from early development; it works fine but isn't
replicated elsewhere.

**Single-runner modular testing.** `test/run.sh` sources modules from
`test/tests/` in numeric order: suite-driven apply (91 tests),
matrix-driven create/convert/undo (89 tests), auto-discovered
info+explain smoke (202 tests), procedural CLI tests (49 tests).
431 tests total. Declarative matrix files (`test/matrix/*.txt`)
define round-trip and conversion test cases. No Haskell test
framework — the tool's correctness is defined by producing the
right bytes, and `sha256sum` is the authority on that.

## Format Support Matrix

| Format | Parse | Apply | Create | Convert | Undo | Info | Explain |
|--------|-------|-------|--------|---------|------|------|---------|
| IPS | ✓ | ✓ | ✓ | ✓‡ | — | ✓ | ✓ |
| IPS32 | ✓ | ✓ | ✓ | ✓‡ | — | ✓ | ✓ |
| EBP | ✓ | ✓ | ✓ | ✓‡ | — | ✓ | ✓ |
| BPS | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| UPS | ✓ | ✓ | ✓ | — | ✓* | ✓ | ✓ |
| PPF1 | ✓ | ✓ | — | ✓‡ | — | ✓ | ✓ |
| PPF2 | ✓ | ✓ | — | ✓‡ | — | ✓ | ✓ |
| PPF3 | ✓ | ✓ | ✓ | ✓‡ | ✓ | ✓ | ✓ |
| PPF4 | ✓ | ✓ | — | — | — | ✓ | ✓ |
| VCDIFF | ✓ | ✓ | — | — | — | ✓ | ✓ |
| BSDiff/BDF | ✓ | ✓† | — | — | — | ✓ | ✓ |
| GDIFF | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| xdelta1 | ✓ | ✓ | — | — | — | ✓ | ✓ |
| APS N64 | ✓ | ✓ | ✓ | ✓‡ | — | ✓ | ✓ |
| APS GBA | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| RUP | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| DPS | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| NINJA1 | ✓ | ✓ | ✓ | ✓‡ | — | ✓ | ✓ |
| PMSR | ✓ | ✓ | ✓ | ✓‡ | — | ✓ | ✓ |

\* UPS undo is self-inverse (apply the patch to the modified file).
† BSDiff falls back to external `bspatch` if the built-in bz2 decompressor fails.
‡ Direct overlay→overlay conversion (no ROM needed). All ‡ formats can convert to any other ‡ format.

## Convert Command

`slap convert PATCH -t FORMAT [--with SOURCE] [-o OUTPUT]`

Two paths:

1. **Overlay→overlay direct conversion** (no ROM needed): Any overlay
   format (IPS, IPS32, EBP, PPF1/2/3, APS-N64, NINJA1, PMSR) can
   convert to any overlay target format. `spDirectConvert` carries a
   `Maybe OverlaySource` — a normalized intermediate representation
   with records, metadata, and format-specific fields. `convertOverlay`
   re-encodes the records into the target format, emitting warnings
   when metadata (descriptions, validation, undo data) must be dropped.
   Offset/size constraints are checked per target (e.g., IPS rejects
   offsets > 16 MB, IPS32 splits records > 65535 bytes).

2. **Apply-then-create** (needs `--with`): Apply the source patch to
   the ROM in memory, then create a new patch from (original, target).
   Works for any input format → any creatable output format, including
   differential formats (BPS, UPS, DPS, RUP, APS-GBA, GDIFF).

InPlace formats go through a temp file for the apply step;
InMemory formats apply directly to the source ByteString.
