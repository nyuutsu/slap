# Architecture

4,300 lines of Haskell. 22 modules. 12 patch formats. One binary.

## Module Map

```
src/
  Main.hs                  753 lines   CLI, closure-based dispatch, convert logic
  Patch/
    Types.hs                 5 lines   PatchFormat enum
    Detect.hs               30 lines   Magic-byte detection → PatchFormat
    Binary.hs              174 lines   Shared primitives: endian readers, varints, CRC32, memcpy
    Get.hs                 176 lines   Pure parser monad (position-threading over strict ByteString)
    Format.hs               66 lines   Display helpers: hex padding, CRC formatting, hex dumps
    Explain.hs             355 lines   Record-by-record textual dumps for all 11 formats
    IPS.hs                 303 lines   IPS + IPS32 + EBP: parse, apply, create, info
    BPS.hs                 233 lines   BPS: parse, apply (unsafeCreate + memcpy), create, info
    UPS.hs                 208 lines   UPS: parse, apply (packZipWith xor), create, info
    VCDIFF.hs              411 lines   VCDIFF/xdelta3: parse, apply (unsafeCreate), info
    BSDiff.hs              161 lines   BSDiff/BDF: parse, apply + external bspatch fallback, info
    GDIFF.hs               152 lines   W3C GDIFF: parse, apply (unsafeCreate), info
    XDelta1.hs             214 lines   xdelta v1.1: parse, gzip decompress, apply (unsafeCreate), info
    APS.hs                 219 lines   APS N64 (type 0+1) + GBA: parse, apply, info
    RUP.hs                 226 lines   RUP/NINJA2: parse, apply, info
    PMSR.hs                176 lines   Paper Mario Star Rod: parse, apply, create, info
    PPF/
      Types.hs              66 lines   PPF types (Patch, Record, Version, ParseError)
      Parse.hs             166 lines   PPF 1/2/3/4 parser
      Apply.hs              68 lines   PPF apply + undo
      Create.hs             92 lines   PPF3 create (IO wrapper + pure core)
      Info.hs               66 lines   PPF info display
```

## Data Flow

```
                          ┌─────────────┐
  file bytes ──→ Detect ──→ PatchFormat ──→ parseSome ──→ SomePatch
                                                              │
                        ┌─────────┬────────┬────────┬────────┘
                        ▼         ▼        ▼        ▼
                     spInfo   spExplain  spApply  spUndo
                    (String)  (String)  (Strategy) (Maybe)
```

`parseSome` is the **only** function that knows about format-specific
types. It parses the raw bytes, then closes over the parsed data to
produce a `SomePatch` — a record of closures carrying all operations.
Every consumer (`doApply`, `doInfo`, `doConvert`, etc.) works through
`SomePatch` fields, never inspecting the underlying format. Adding
format #12 means adding one block to `parseSome`. Nothing else changes.

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
  , spRecordCount    :: Int
  , spRecordUnit     :: String
  , spDirectConvert  :: CreateFormat -> Maybe (Either String BS.ByteString)
  }

data ApplyStrategy
  = InPlace (FilePath -> IO ())
  | InMemory (BS.ByteString -> IO (Either String BS.ByteString))
             (Maybe Word32)   -- source CRC
             (Maybe Word32)   -- target CRC
```

This is what a typeclass + existential compiles to, but without the
language extensions, module layering constraints, or indirection. The
parsed format-specific data is captured in closures at construction
time. The key tradeoff: you lose the ability to pattern-match on
`SomeIPS` vs `SomeBPS`, but nothing outside `parseSome` needs to.

Apply functions split into two strategies:

1. **InMemory** (BPS, UPS, VCDIFF, BSDiff, GDIFF, XDelta1):
   Takes source ByteString, returns target ByteString.
   Uses `unsafeCreate` + raw pointer writes for output buffers.

2. **InPlace** (IPS, PPF, APS, RUP, PMSR):
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

**Suite-based testing.** Declarative `.suite` manifests in
`test/suites/` with a 140-line bash runner. Each suite declares a
base ROM, expected SHA256, and a list of patches with confidence
levels (gold/verified/untested/broken). The runner applies each
patch to a temp copy and verifies the hash. No Haskell test
framework — the tool's correctness is defined by producing the
right bytes, and `sha256sum` is the authority on that.

## Format Support Matrix

| Format | Parse | Apply | Create | Undo | Info | Explain |
|--------|-------|-------|--------|------|------|---------|
| IPS | ✓ | ✓ | ✓ | — | ✓ | ✓ |
| IPS32 | ✓ | ✓ | ✓ | — | ✓ | ✓ |
| EBP | ✓ | ✓ | — | — | ✓ | ✓ |
| BPS | ✓ | ✓ | ✓ | — | ✓ | ✓ |
| UPS | ✓ | ✓ | ✓ | ✓* | ✓ | ✓ |
| PPF1 | ✓ | ✓ | — | — | ✓ | ✓ |
| PPF2 | ✓ | ✓ | — | — | ✓ | ✓ |
| PPF3 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| PPF4 | ✓ | ✓ | — | — | ✓ | ✓ |
| VCDIFF | ✓ | ✓ | — | — | ✓ | ✓ |
| BSDiff/BDF | ✓ | ✓† | — | — | ✓ | ✓ |
| GDIFF | ✓ | ✓ | — | — | ✓ | ✓ |
| xdelta1 | ✓ | ✓ | — | — | ✓ | ✓ |
| APS N64 | ✓ | ✓ | — | — | ✓ | ✓ |
| APS GBA | ✓ | ✓ | — | — | ✓ | ✓ |
| RUP | ✓ | ✓ | — | — | ✓ | ✓ |
| PMSR | ✓ | ✓ | ✓ | — | ✓ | ✓ |

\* UPS undo is self-inverse (apply the patch to the modified file).
† BSDiff falls back to external `bspatch` if the built-in bz2 decompressor fails.

## Convert Command

`slap convert PATCH -t FORMAT [--with SOURCE] [-o OUTPUT]`

Two paths:

1. **Direct conversion** (no ROM needed): IPS↔IPS32 only. Re-encodes
   records with wider/narrower offsets. Stored as a `spDirectConvert`
   closure on `SomePatch`.

2. **Apply-then-create** (needs `--with`): Apply the source patch to
   the ROM in memory, then create a new patch from (original, target).
   Works for any input format → any creatable output format.

InPlace formats go through a temp file for the apply step;
InMemory formats apply directly to the source ByteString.
