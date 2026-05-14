{-# LANGUAGE OverloadedStrings #-}

-- | xdelta1 patch creation.
--
-- The wire encoder ('encodeXDelta1') is the round-trip partner of
-- 'Slap.XDelta1.Parse.parseControl' /
-- 'Slap.XDelta1.Parse.parseVersion1Point1': given an 'XDelta1Patch'
-- value, it produces wire bytes that 'Slap.XDelta1.Parse.parseXDelta1'
-- reads back to an equal patch. 'createXDelta1' chains the rsync-
-- style differ in "Slap.XDelta1.FFI" (kernel in
-- @rusty-slap\/src\/xdelta1_diff.rs@) onto the encoder: the differ
-- owns the rolling-checksum index over source, the byte-by-byte
-- target walk, and the per-source sequential-mode tracking; this
-- module owns the MD5s, the 'VerificationInclusion' wiring, the
-- 'XDelta1PatchCompression' wiring, and 'XDelta1Patch' assembly.
--
-- == @FLAG_PATCH_COMPRESSED@
--
-- Gated by 'Slap.XDelta1.Types.XDelta1PatchCompression', threaded
-- in from the porcelain. Under 'CompressedPatch' (default) the bit
-- is set and the data and control segments are gzip-deflated
-- independently before placement. Under 'UncompressedPatch' (set
-- by @slap create --no-compress@) the bit stays clear and the
-- segments are emitted raw. Both shapes are spec-conformant;
-- canonical xdelta-1.x emits compressed by default.
--
-- == @FLAG_NO_VERIFY@
--
-- Gated by 'Slap.MetadataInclusion.VerificationInclusion', threaded
-- in from the porcelain. Under 'IncludeVerification' (default) the
-- bit stays clear, real MD5s are computed and written for the
-- target, the data source, and the file source. Under
-- 'OmitVerification' (set by @slap create --no-verify@) the bit is
-- set, the patch's verification posture is
-- 'CreatorOptedOutOfVerification', and the sentinel
-- ('xdelta1EmptyInputMD5Sentinel') is written into every MD5 slot
-- — matching what canonical xdelta's @--noverify@ produces.
module Slap.XDelta1.Create
  ( createXDelta1
  ) where

import Slap.Compression.Stream (gzipDeflate)
import Slap.MetadataInclusion (VerificationInclusion(..))
import Slap.XDelta1.FFI
    ( XDelta1DiffOutput(..)
    , xdelta1Diff
    )
import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Sources(..)
    , XDelta1Instruction(..), XDelta1InstructionTarget(..)
    , XDelta1OffsetMode(..)
    , XDelta1SourceWireKind(..)
    , XDelta1VerificationPosture(..)
    , XDelta1PatchCompression(..)
    , XDelta1FileAtDeltaTime(..)
    , xdelta1EmptyInputMD5Sentinel
    , xdelta1FlagNoVerify
    , xdelta1FlagFromCompressed
    , xdelta1FlagToCompressed
    , xdelta1FlagPatchCompressed
    , xdelta1ControlTypeTag
    , xdelta1ControlAllocationBound
    )
import Slap.Binary (md5, putEdsioVarint, word32BEBytes)
import Slap.Checksum (MD5Hash(..))
import Slap.Error (SlapError, CreateResult(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..),
                          PatchFileContents(..))
import Slap.Measure (Offset(..), FileSize(..), byteFileSize)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, byteString, toLazyByteString, word8)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Bits (shiftL, (.|.))
import Data.Word (Word8, Word32, Word64)

----------------------------------------------------------------------------
-- Top-level entry
----------------------------------------------------------------------------

-- | Create an xdelta1 patch from source and target bytes. The differ
-- ('Slap.XDelta1.FFI.xdelta1Diff') produces the instruction
-- stream and the data segment; this function wraps them in an
-- 'XDelta1Patch' value (computing MD5s and choosing the offset mode
-- per source) and runs the wire encoder.
--
-- The 'VerificationInclusion' choice (set by @slap create
-- --no-verify@ at the porcelain) gates two paired wire effects:
-- under 'OmitVerification' the patch's verification posture is
-- 'CreatorOptedOutOfVerification', the @FLAG_NO_VERIFY@ header
-- bit is set, and every MD5 slot carries
-- 'xdelta1EmptyInputMD5Sentinel'; under 'IncludeVerification' the
-- posture is 'VerifyAgainstStoredMD5s' with computed hashes and
-- the bit is clear.
--
-- The 'XDelta1PatchCompression' choice (set by @slap create
-- --no-compress@ at the porcelain) decides whether the data and
-- control segments are gzip-deflated independently before placement
-- and whether @FLAG_PATCH_COMPRESSED@ is set.
createXDelta1 :: VerificationInclusion -> XDelta1PatchCompression
              -> InputFileContents -> OutputFileContents
              -> Either SlapError CreateResult
createXDelta1 inclusion compression inputContents outputContents =
  case xdelta1Diff inputContents outputContents of
    Left slapError -> Left slapError
    Right diff ->
      let sourceBytes = unInputFileContents inputContents
          targetBytes = unOutputFileContents outputContents
          patch       = assemblePatch inclusion compression sourceBytes targetBytes diff
          wireBytes   = encodeXDelta1 patch
      in  Right (CreateResult (PatchFileContents wireBytes) [])

----------------------------------------------------------------------------
-- Differ output → XDelta1Patch
----------------------------------------------------------------------------

-- | Wrap a 'XDelta1DiffOutput' (instructions + data segment + the
-- per-source sequential-mode flags) into an 'XDelta1Patch' ready
-- for the wire encoder. The MD5s, the 'VerificationInclusion'
-- wiring, and the 'XDelta1PatchCompression' wiring live here; the
-- differ doesn't know about them.
assemblePatch
  :: VerificationInclusion -> XDelta1PatchCompression
  -> ByteString -> ByteString
  -> XDelta1DiffOutput -> XDelta1Patch
assemblePatch inclusion compression sourceBytes targetBytes diff = XDelta1Patch
  { xdelta1FromName         = "source"
  , xdelta1ToName           = "target"
  , xdelta1Verification     = verificationPosture
  , xdelta1PatchCompression = compression
    -- Slap doesn't detect gzip-magic on inputs at create time, so
    -- both inputs are recorded as raw bytes. The encoder still
    -- handles either case because slap convert round-trips parsed
    -- xdelta1 patches that may have these bits set.
  , xdelta1FromAtDeltaTime  = FileWasRawBytes
  , xdelta1ToAtDeltaTime    = FileWasRawBytes
  , xdelta1TargetLength     = byteFileSize targetBytes
  , xdelta1Sources          = XDelta1Sources
      { xdelta1DataSource = XDelta1Source
          { xdelta1SourceName       = "(patch data)"
          , xdelta1SourceMD5        = perSourceMD5 dataSegmentMD5
          , xdelta1SourceLength     = byteFileSize dataSegmentBytes
          , xdelta1SourceOffsetMode = offsetMode (xdelta1DiffDataSourceIsSequential diff)
          }
      , xdelta1FileSource = XDelta1Source
          { xdelta1SourceName       = "source"
          , xdelta1SourceMD5        = perSourceMD5 sourceMD5
          , xdelta1SourceLength     = byteFileSize sourceBytes
          , xdelta1SourceOffsetMode = offsetMode (xdelta1DiffFileSourceIsSequential diff)
          }
      }
  , xdelta1Instructions     = xdelta1DiffInstructions diff
  , xdelta1DataSegment      = dataSegmentBytes
  }
  where
    dataSegmentBytes = xdelta1DiffDataSegment diff
    targetMD5        = md5 targetBytes
    sourceMD5        = md5 sourceBytes
    dataSegmentMD5   = md5 dataSegmentBytes

    verificationPosture = case inclusion of
      IncludeVerification -> VerifyAgainstStoredMD5s targetMD5
      OmitVerification    -> CreatorOptedOutOfVerification

    perSourceMD5 computedMD5 = case inclusion of
      IncludeVerification -> Just computedMD5
      OmitVerification    -> Nothing

    offsetMode True  = SequentialOffsets
    offsetMode False = AbsoluteOffsets

----------------------------------------------------------------------------
-- Wire encoder
----------------------------------------------------------------------------

-- | Encode an 'XDelta1Patch' value to wire bytes. Mirror image of
-- 'Slap.XDelta1.Parse.parseVersion1Point1' across the @%XDZ004%@
-- (xdelta 1.1.x) shape: produces wire bytes that
-- 'Slap.XDelta1.Parse.parseXDelta1' reads back to an equal patch
-- under either verification posture and either compression
-- posture.
--
-- Layout:
--
--   1. Magic prefix:        @%XDZ004%@ (8 bytes)
--   2. Header words:        6 × uint32 BE (flags, name lengths,
--                           4 reserved zero words)
--   3. From-name bytes
--   4. To-name bytes
--   5. Data segment         (compressed when the patch's
--                           'xdelta1PatchCompression' is
--                           'CompressedPatch'; gated on the
--                           @FLAG_PATCH_COMPRESSED@ bit)
--   6. Control segment      (EDSIO-serialized @XdeltaControl@,
--                           same compression gating as the data
--                           segment — each segment is its own
--                           gzip stream)
--   7. Control offset:      uint32 BE (file offset where segment 6 begins)
--   8. Trailing magic:      @%XDZ004%@ (8 bytes)
encodeXDelta1 :: XDelta1Patch -> ByteString
encodeXDelta1 patch = ByteString.concat
  [ magicBytes
  , headerBytes
  , xdelta1FromName patch
  , xdelta1ToName patch
  , dataSegment
  , controlSegment
  , word32BEBytes controlOffset
  , magicBytes
  ]
  where
    magicBytes     = "%XDZ004%"
    fromNameLength = ByteString.length (xdelta1FromName patch)
    toNameLength   = ByteString.length (xdelta1ToName patch)

    -- Flags word: @FLAG_NO_VERIFY@ (bit 0) tracks the patch's
    -- verification posture; @FLAG_FROM_COMPRESSED@ (bit 1) and
    -- @FLAG_TO_COMPRESSED@ (bit 2) track whether the from- or
    -- to-file was a gzip stream at delta time (round-trip honest —
    -- slap doesn't emit these bits from create, but preserves
    -- them from parsed patches under convert); @FLAG_PATCH_COMPRESSED@
    -- (bit 3) tracks the patch's compression posture.
    flagsWord = noVerifyBit .|. fromCompressedBit .|. toCompressedBit .|. compressionBit
      where
        noVerifyBit = case xdelta1Verification patch of
          VerifyAgainstStoredMD5s _     -> 0
          CreatorOptedOutOfVerification -> xdelta1FlagNoVerify
        fromCompressedBit = case xdelta1FromAtDeltaTime patch of
          FileWasRawBytes   -> 0
          FileWasGzipStream -> xdelta1FlagFromCompressed
        toCompressedBit = case xdelta1ToAtDeltaTime patch of
          FileWasRawBytes   -> 0
          FileWasGzipStream -> xdelta1FlagToCompressed
        compressionBit = case xdelta1PatchCompression patch of
          UncompressedPatch -> 0
          CompressedPatch   -> xdelta1FlagPatchCompressed
    nameLengthsWord = fromIntegral (fromNameLength `shiftL` 16 .|. toNameLength) :: Word32
    reservedWord    = 0 :: Word32
    headerBytes = ByteString.concat
      [ word32BEBytes flagsWord
      , word32BEBytes nameLengthsWord
      , word32BEBytes reservedWord
      , word32BEBytes reservedWord
      , word32BEBytes reservedWord
      , word32BEBytes reservedWord
      ]

    -- Each segment is gzip-deflated independently under
    -- 'CompressedPatch' (the parser inflates each independently);
    -- under 'UncompressedPatch' they're emitted raw. The
    -- 'controlOffset' arithmetic reads 'ByteString.length
    -- dataSegment' below, so it's automatically correct under
    -- either posture.
    applyCompression bytes = case xdelta1PatchCompression patch of
      CompressedPatch   -> gzipDeflate bytes
      UncompressedPatch -> bytes
    dataSegment    = applyCompression (xdelta1DataSegment patch)
    controlSegment = applyCompression (encodeControl patch)

    -- File offset where the control segment begins.
    controlOffset :: Word32
    controlOffset = fromIntegral $
      ByteString.length magicBytes
      + ByteString.length headerBytes
      + fromNameLength
      + toNameLength
      + ByteString.length dataSegment

----------------------------------------------------------------------------
-- Control segment encoder
----------------------------------------------------------------------------

-- | Encode the EDSIO-serialized control structure (mirror image of
-- 'Slap.XDelta1.Parse.parseControlBody'): the canonical
-- @ST_XdeltaControl@ type tag ('xdelta1ControlTypeTag', 4 BE bytes),
-- a parser-scratch allocation upper bound
-- ('xdelta1ControlAllocationBound', 4 BE bytes), the target MD5, a
-- varint target length, the @has_data@ boolean, the source list
-- (always two records, in @[data, file]@ order), and the instruction
-- list.
--
-- The two prelude words are non-negotiable: canonical xdelta's
-- generic EDSIO reader (@libedsio\/generic.c:66@) bails immediately
-- with "Unregistered library: 0" when the type tag's low byte
-- isn't a registered library number, and its sub-allocation
-- accountant (@libedsio\/default.c@) caps every reconstructed
-- pointer at the declared allocation bound. Slap's own parser
-- previously skipped both fields without inspection, which is why
-- the all-zeros prelude this encoder used to emit round-tripped
-- under slap but was rejected by canonical.
encodeControl :: XDelta1Patch -> ByteString
encodeControl patch = LazyByteString.toStrict (toLazyByteString builder)
  where
    builder =
      byteString (word32BEBytes xdelta1ControlTypeTag)
      <> byteString (word32BEBytes xdelta1ControlAllocationBound)
      <> byteString (unMD5Hash toMD5Bytes)
      <> putEdsioVarint (fromIntegral (unFileSize (xdelta1TargetLength patch)))
      <> word8 1  -- has_data flag: nonzero means a data segment follows
      <> putEdsioVarint 2  -- two source records: the data source, then the file source
      <> encodeSource (xdelta1DataSource sources) WireKindData
      <> encodeSource (xdelta1FileSource sources) WireKindFile
      <> putEdsioVarint (fromIntegral (length instructions))
      <> foldMap (encodeInstruction sources) instructions

    sources      = xdelta1Sources patch
    instructions = xdelta1Instructions patch

    -- Target MD5 lives inside the posture under
    -- 'VerifyAgainstStoredMD5s' and is the empty-input sentinel
    -- under 'CreatorOptedOutOfVerification' (matching what
    -- canonical xdelta's @--noverify@ writes).
    toMD5Bytes = case xdelta1Verification patch of
      VerifyAgainstStoredMD5s md5Hash    -> md5Hash
      CreatorOptedOutOfVerification      -> xdelta1EmptyInputMD5Sentinel

encodeSource :: XDelta1Source -> XDelta1SourceWireKind -> Builder
encodeSource source wireKind =
  putEdsioVarint (fromIntegral (ByteString.length (xdelta1SourceName source)))
  <> byteString (xdelta1SourceName source)
  <> byteString (unMD5Hash sourceMD5Bytes)
  <> putEdsioVarint (fromIntegral (unFileSize (xdelta1SourceLength source)))
  <> word8 (sourceWireKindByte wireKind)
  <> word8 (offsetModeByte (xdelta1SourceOffsetMode source))
  where
    sourceMD5Bytes = case xdelta1SourceMD5 source of
      Just md5Hash -> md5Hash
      Nothing      -> xdelta1EmptyInputMD5Sentinel

-- | Encode one instruction. The offset field is written as 0 when the
-- applicable source is in 'SequentialOffsets' mode (the parser at
-- 'Slap.XDelta1.Parse.fixSequentialOffsets' reconstructs the absolute
-- offset from the running cumulative length); under 'AbsoluteOffsets'
-- the offset is written verbatim. The applicable source is the one
-- this instruction targets (data or file), looked up via
-- 'xdelta1InstructionTarget'.
encodeInstruction :: XDelta1Sources -> XDelta1Instruction -> Builder
encodeInstruction sources instruction =
  putEdsioVarint (instructionTargetWireIndex (xdelta1InstructionTarget instruction))
  <> offsetVarint
  <> putEdsioVarint (fromIntegral (unFileSize (xdelta1InstructionLength instruction)))
  where
    instructionSource = case xdelta1InstructionTarget instruction of
      FromDataSource -> xdelta1DataSource sources
      FromFileSource -> xdelta1FileSource sources
    offsetVarint = case xdelta1SourceOffsetMode instructionSource of
      SequentialOffsets -> putEdsioVarint 0
      AbsoluteOffsets   -> putEdsioVarint (fromIntegral (unOffset (xdelta1InstructionOffset instruction)))

-- | Wire byte for the source-kind slot of an EDSIO source record.
-- Inverse of the parser's @sourceKindByte \/= 0@ test
-- ('Slap.XDelta1.Parse.parseOneSource'): canonical xdelta writes
-- @1@ for the data source and @0@ for the file source.
sourceWireKindByte :: XDelta1SourceWireKind -> Word8
sourceWireKindByte WireKindData = 1
sourceWireKindByte WireKindFile = 0

-- | Wire byte for the offset-mode slot of an EDSIO source record.
-- Inverse of the parser's @offsetModeByte \/= 0@ test
-- ('Slap.XDelta1.Parse.parseOneSource').
offsetModeByte :: XDelta1OffsetMode -> Word8
offsetModeByte SequentialOffsets = 1
offsetModeByte AbsoluteOffsets   = 0

-- | Wire source-index for an instruction. Inverse of the parser's
-- 'Slap.XDelta1.Parse.translateInstruction': the data source is
-- referenced by index @0@ and the file source by index @1@.
instructionTargetWireIndex :: XDelta1InstructionTarget -> Word64
instructionTargetWireIndex FromDataSource = 0
instructionTargetWireIndex FromFileSource = 1
