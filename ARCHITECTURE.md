# Architecture

~7,300 lines of Haskell. 29 modules. 16 patch formats. One binary.

## Module Map

```
app/
  Main.hs          CLI parsing, command handlers
src/
  Patch/
    SomePatch.hs   SomePatch existential, ApplyStrategy, Verification, parseSome dispatch
    Convert.hs     PatchContents, FormatSpec, contract checking, direct conversion, createFromMemory
    Types.hs       PatchFormat enum
    Detect.hs      Magic-byte detection → PatchFormat
    Binary.hs      Shared primitives: endian readers, varints, CRC32, MD5, SHA1, memcpy
    Get.hs         Pure parser monad (position-threading over strict ByteString)
    Format.hs      Display helpers: hex padding, CRC formatting, hex dumps
    Explain.hs     Structured explain data types, per-format explain functions, shared renderer
    Archive.hs     ZIP/RAR/7z detection + single-entry extraction
    IPS.hs         IPS + IPS32 + EBP: parse, apply, create, info
    BPS.hs         BPS: parse, apply (unsafeCreate + memcpy), create, info
    UPS.hs         UPS: parse, apply (packZipWith xor), create, info
    VCDIFF.hs      VCDIFF/xdelta3: parse, apply (unsafeCreate), info
    BSDiff.hs      BSDiff/BDF: parse, apply + safe bzip2 decompress, info
    GDIFF.hs       W3C GDIFF: parse, apply (unsafeCreate), create, info
    XDelta1.hs     xdelta v1.1: parse, gzip decompress, apply (unsafeCreate), info
    APS.hs         APS N64 (type 0+1) + GBA: parse, apply, create, info
    RUP.hs         RUP/NINJA2: parse, apply, create, info
    DPS.hs         DPS: parse, apply, create, info
    NINJA1.hs      NINJA1 (B/BZ/T/TZ): parse, apply, create, info
    PMSR.hs        Paper Mario Star Rod: parse, apply, create, info
    PCHTXT.hs      PCHTXT (Nintendo Switch): parse, apply, create, info
    Yay0.hs        Nintendo LZSS decompression for Star Rod .mod files
    PPF/
      Types.hs     PPF types (Patch, Record, Version)
      Parse.hs     PPF 1/2/3/4 parser
      Apply.hs     PPF apply + undo
      Create.hs    PPF3 create (IO wrapper + pure core)
      Info.hs      PPF info display
test/
  Props.hs         QuickCheck: 15 round-trip + 2 hash + 16 truncation + 6 contract properties
```

## Data Flow

```
                          ┌─────────────┐
  file bytes ──→ Detect ──→ PatchFormat ──→ parseSome ──→ SomePatch
                                                              │
                  ┌─────────┬────────┬────────┬──────────┬────┘
                  ▼         ▼        ▼        ▼          ▼
               spInfo   spExplain  spApply  spVerify  spContents
              (String) (ExplainData) (Strategy) (Verif)  (Maybe PatchContents)
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
  , spExplain        :: ExplainData
  , spIsDifferential :: Bool
  , spApply          :: ApplyStrategy
  , spUndo           :: Maybe UndoStrategy
  , spVerification   :: Verification
  , spVerboseLines   :: [String]
  , spWarnings       :: [String]
  , spRecordCount    :: Int
  , spRecordUnit     :: String
  , spContents       :: Maybe PatchContents
  }

data ApplyStrategy
  = InPlace (FilePath -> IO ())
  | InMemory
      { imApply :: BS.ByteString -> IO (Either String BS.ByteString) }

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

2. **InPlace** (IPS, PPF, APS, RUP, NINJA1, PMSR, PCHTXT):
   Seeks and writes into a mutable file. Used for formats that
   were designed for in-place patching.

## Verification

```haskell
data Verification = Verification
  { vSourceCRC32  :: Maybe Word32
  , vSourceMD5    :: Maybe BS.ByteString
  , vSourceSHA1   :: Maybe BS.ByteString
  , vTargetCRC32  :: Maybe Word32
  , vTargetMD5    :: Maybe BS.ByteString
  , vSourceBlocks :: [(Int, Word16)]      -- APS-GBA per-block CRC16
  , vTargetBlocks :: [(Int, Word16)]
  , vPPFBlock     :: Maybe (Int64, BS.ByteString)
  }
```

Every `SomePatch` carries a `Verification` record populated by
`parseSome` from whatever the parsed format provides. All checksum
validation flows through `verifySource`/`verifyTarget` in Main.hs,
which inspect `spVerification` fields — format modules never check
hashes themselves.

Three tiers of verification:

1. **Whole-file hashes** (CRC32, MD5, SHA1): Fatal by default.
   `--no-verify` downgrades mismatches to warnings.
   Formats: BPS/UPS (source+target CRC32), NINJA1 (source CRC32+MD5+SHA1),
   RUP (source+target MD5), xdelta1 (source+target MD5).

2. **Advisory spot-checks** (PPF validation block, APS-GBA per-block CRC16):
   Warning-only regardless of `--no-verify`.

3. **Patch file integrity** (BPS/UPS patch CRC): Always checked, cannot
   be bypassed.

## Conversion — Contract System

`Patch.Convert` defines a declarative contract system for direct
direct format conversion.

```haskell
data PatchField = FRecords | FDescription | FSourceCRC32 | FSourceMD5
                | FSourceSHA1 | FDestSize | FUndoData | FValidation
                | FTruncation | FEBPMeta

data FormatSpec = FormatSpec
  { fsRequired :: Set PatchField   -- must be present or conversion fails
  , fsAccepted :: Set PatchField   -- carried through if available
  }

data PatchContents = PatchContents
  { pcRecords, pcDescription, pcSourceCRC32, pcSourceMD5, pcSourceSHA1,
    pcDestSize, pcValidation, pcUndoData, pcTruncation, pcEBPMeta }
```

`parseSome` populates `spContents :: Maybe PatchContents` for direct
formats (IPS, IPS32, EBP, PPF1/2/3, APS-N64, NINJA1, PMSR, PCHTXT).
Differential formats set it to `Nothing`.

`convertDirect` checks `canConvert pc spec` — if the source contents
satisfy the target spec's required fields, conversion proceeds.
Otherwise, the error names the missing fields and suggests `--with`.

`conversionNotes` compares `provides pc` against `fsRequired ∪ fsAccepted`
to identify surplus fields that will be dropped, emitting notes like
"dropping source CRC32: 0xDEADBEEF" on stderr.

Two conversion paths:

1. **Direct** (no ROM needed): `spContents` is `Just` and
   `canConvert` succeeds. `encodeDirect` dispatches to per-format
   encoders. Offset/size constraints are checked per target (IPS/EBP
   reject offsets > 16 MB, IPS32 splits records > 65535 bytes).

2. **Apply-then-create** (needs `--with`): Apply the source patch to
   the ROM in memory, then create a new patch from (original, target)
   via `createFromMemory`. Works for any input format → any creatable
   output format, including differential formats.

InPlace formats go through a temp file for the apply step;
InMemory formats apply directly to the source ByteString.

The conversion system is descriptive: each format declares what fields
it requires, accepts, and provides. `canConvert` checks whether the
source's provided fields satisfy the target's requirements — it doesn't
maintain a table of allowed conversions. Most format pairs can't convert
directly (the source lacks fields the target needs), so `--with` triggers
an apply-then-create path instead. This is emergent from the field
contracts, not hardcoded. Adding fields to a format's `spContents`
automatically unlocks new direct conversions without touching dispatch
logic.

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
safety that no consumer benefits from.

**Two-layer testing.** Integration tests (`test/run.sh`, 507 tests)
use SHA256 verification against real patches and external tools.
Property tests (`test/Props.hs`, 39 QuickCheck properties) test
round-trip correctness, parser robustness, and conversion contracts.
Declarative matrix files (`test/specs/*.txt`) define round-trip,
conversion, and cross-validation test cases.

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
| PCHTXT | ✓ | ✓ | ✓ | ✓‡ | — | ✓ | ✓ |

\* UPS undo is self-inverse (apply the patch to the modified file).
† BSDiff falls back to external `bspatch` if the built-in bz2 decompressor fails.
‡ Direct format conversion (no ROM needed). All ‡ formats can convert to any other ‡ format.
