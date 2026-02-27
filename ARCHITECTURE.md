# Architecture

Haskell + Rust.

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
    Binary.hs      Shared primitives: endian readers, varints, CRC-16, MD5, SHA1, memcpy
    FFI.hs         Rust FFI: rustyCRC32, rustyAdler32, rustyBpsDiff
    Compress.hs    Rust FFI: zlibInflate/Deflate, gzipInflate, bz2Decompress
    Get.hs         Pure parser monad (position-threading over strict ByteString)
    Format.hs      Display helpers: hex padding, CRC formatting, hex dumps
    Explain.hs     Structured explain data types, per-format explain functions, shared renderer
    Archive.hs     ZIP/RAR/7z detection + single-entry extraction
    IPS.hs         IPS + IPS32 + EBP: parse, apply, create, info
    BPS.hs         BPS: parse, apply (unsafeCreate + memcpy), create (via Rust diff), info
    UPS.hs         UPS: parse, apply (packZipWith xor), create, info
    VCDIFF.hs      VCDIFF/xdelta3: parse, apply (unsafeCreate), info
    BSDiff.hs      BSDiff/BDF: parse, apply, info
    GDIFF.hs       W3C GDIFF: parse, apply (unsafeCreate), create, info
    XDelta1.hs     xdelta v1.1: parse, apply (unsafeCreate), info
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
rusty-slap/src/
  lib.rs           FFI boundary (extern "C" exports, pointer ↔ slice, write_vec_to_ffi)
  crc32.rs         CRC-32 via crc32fast (hardware CLMUL/PCLMULQDQ)
  sa.rs            SA-IS suffix array (linear-time, Nong/Zhang/Chan 2009)
  bps_diff.rs      BPS diff engine (concatenated SA + progressive sorting, after Alcaro/Flips)
  compress.rs      flate2 (zlib/gzip) + bzip2-rs (bzip2), pure Rust
test/
  Props.hs         QuickCheck properties (round-trip, parse-truncated, contract)
```

## Data Flow

`parseSome` is the **only** function that knows about format-specific
types. It parses the raw bytes, then closes over the parsed data to
produce a `SomePatch` — a record of closures carrying all operations.
Every consumer (`doApply`, `doInfo`, `doConvert`, etc.) works through
`SomePatch` fields, never inspecting the underlying format. Adding a
new format means adding one block to `parseSome`. Nothing else changes.

## SomePatch — Closure-Based Existential

`SomePatch` is a record of closures — what a typeclass + existential
compiles to, without the language extensions or module layering.
`parseSome` captures format-specific data in closures at construction
time; consumers use field accessors, never pattern-match on formats.

## Verification

Checksum validation flows through `verifySource`/`verifyTarget` in
Main.hs — format modules never check hashes themselves. Three tiers:

1. **Whole-file hashes** (CRC32, MD5, SHA1): Fatal by default.
   `--no-verify` downgrades mismatches to warnings.
   Formats: BPS/UPS (source+target CRC32), NINJA1 (source CRC32+MD5+SHA1),
   RUP (source+target MD5), xdelta1 (source+target MD5).

2. **Advisory spot-checks** (PPF validation block, APS-GBA per-block CRC16):
   Warning-only regardless of `--no-verify`.

3. **Patch file integrity** (BPS/UPS patch CRC): Always checked, cannot
   be bypassed.

## Conversion — Contract System

`Patch.Convert` defines a contract system for direct format conversion.
Each target format declares required and accepted fields (`FormatSpec`).
Each parsed overlay patch exposes its fields (`PatchContents`).

`parseSome` populates `spContents :: Maybe PatchContents` for direct
formats (IPS, IPS32, EBP, PPF1/2/3, APS-N64, NINJA1, PMSR, PCHTXT).
Differential formats set it to `Nothing`. PPF4 sets it to `Nothing`
when Append records are present (offsets would be wrong).

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
   via `createFromMemory`.

## Key Design Decisions

**Closure-based existential, not sum type or typeclass.** `SomePatch`
is a record of closures — the same thing a typeclass + existential
compiles to, without the language extensions or module layering.
`parseSome` constructs the record; consumers use field accessors.
Each format module stays self-contained.

**Patch.Get monad, not attoparsec/binary/cereal.** 176 lines,
no dependencies, position tracking, bounded reads, error messages
with byte offsets.

**Builder for output, unsafeCreate for apply.** Patch creation uses
`Data.ByteString.Builder` (lazy construction, efficient concat).
Patch application uses `unsafeCreate` with raw pointer arithmetic
(single allocation, memcpy-speed bulk copies via `copyBSRange`).
The distinction matters: creation builds output incrementally from
diffs, while application reconstructs a known-size target buffer.

## rusty-slap — Rust Static Library

`rusty-slap/` is a Rust `staticlib` linked into the Haskell binary
via `ccall unsafe` FFI.

**What Rust owns:**
- CRC-32 (hardware CLMUL/PCLMULQDQ via `crc32fast`)
- Adler-32 (RFC 1950)
- BPS diff (SA-IS suffix array + concatenated-SA algorithm, after Alcaro's Flips)
- Compression: zlib/gzip (`flate2`/`miniz_oxide`), bzip2 (`bzip2-rs`)

**What Haskell keeps:** parsing, format logic, conversion, CLI, types.

**FFI boundary:** `Patch.FFI` (checksums, BPS diff) and `Patch.Compress`
(zlib, gzip, bzip2). Rust allocates output buffers via `Box<[u8]>`;
Haskell copies with `packCStringLen`, then frees via `rusty_free`.

**Build:** `Makefile` orchestrates `cargo build --release` then
`cabal build --extra-lib-dirs=...`. A `.rusty-stamp` file detects when
the Rust `.a` changes and triggers `cabal clean` (cabal 3.14 uses
content hashing, so mtime tricks don't work).

**Dependencies:** All Rust crates are pure Rust. The final binary has
no runtime dependency on libz, libbz2, or any system C library beyond
what GHC requires (libc, libm, libgmp).

Release profile: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`,
`RUSTFLAGS += -C target-cpu=native`.
