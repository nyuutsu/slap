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
    ( XDelta1Patch(..)
    , XDelta1Instruction(..), XDelta1InstructionTarget(..)
    , XDelta1OffsetMode(..)
    , XDelta1VerificationPosture(..)
    , XDelta1PatchCompression(..)
    , XDelta1FileAtDeltaTime(..)
    , xdelta1EmptyInputMD5Sentinel
    , xdelta1DataRecordName
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
-- differ doesn't know about them. The data-record's metadata (name,
-- MD5, length, offset-mode) doesn't live on the patch type — those
-- values are inline constants in 'encodeControl' below, derived from
-- the data-segment bytes and 'xdelta1DataRecordName'.
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
  , xdelta1SourceName       = "source"
  , xdelta1SourceMD5        = perSourceMD5 (md5 sourceBytes)
  , xdelta1SourceLength     = byteFileSize sourceBytes
  , xdelta1SourceOffsetMode = xdelta1DiffFileSourceOffsetMode diff
  , xdelta1Instructions     = xdelta1DiffInstructions diff
  , xdelta1DataSegment      = xdelta1DiffDataSegment diff
  }
  where
    targetMD5 = md5 targetBytes

    verificationPosture = case inclusion of
      IncludeVerification -> VerifyAgainstStoredMD5s targetMD5
      OmitVerification    -> CreatorOptedOutOfVerification

    perSourceMD5 computedMD5 = case inclusion of
      IncludeVerification -> Just computedMD5
      OmitVerification    -> Nothing

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
--
-- The data-record's wire bytes (name, MD5, length, kind, offset-
-- mode) are inline constants here: name is 'xdelta1DataRecordName';
-- MD5 is computed from the data-segment bytes (or the sentinel
-- under 'CreatorOptedOutOfVerification'); length is the data
-- segment's byte count; kind byte is @1@ (data); offset-mode byte
-- is @1@ (sequential — slap's differ never emits non-sequential
-- data emits). The source-file record's bytes come from the patch's
-- flat @xdelta1Source*@ fields.
encodeControl :: XDelta1Patch -> ByteString
encodeControl patch = LazyByteString.toStrict (toLazyByteString builder)
  where
    builder =
      byteString (word32BEBytes xdelta1ControlTypeTag)
      <> byteString (word32BEBytes xdelta1ControlAllocationBound)
      <> byteString (unMD5Hash toMD5Bytes)
      <> putEdsioVarint (fromIntegral (unFileSize (xdelta1TargetLength patch)))
      <> word8 hasDataByte
      <> putEdsioVarint 2  -- two source records: the data record, then the file source
      <> encodeDataRecord patch
      <> encodeFileSourceRecord patch
      <> putEdsioVarint (fromIntegral (length instructions))
      <> foldMap (encodeInstruction patch) instructions

    instructions = xdelta1Instructions patch

    -- @has_data@ is set when the data segment is non-empty. Canonical
    -- xdelta clears the byte when the differ found the entire target
    -- by copies from the source file with no inline literals
    -- (@xdelta.c:1082@). The parser at
    -- 'Slap.XDelta1.Parse.parseControlBody' reads and discards the
    -- byte; slap's apply ignores it because the data-segment bytes
    -- carry their own length via the patch envelope.
    hasDataByte :: Word8
    hasDataByte
      | ByteString.null (xdelta1DataSegment patch) = 0
      | otherwise                                  = 1

    -- Target MD5 lives inside the posture under
    -- 'VerifyAgainstStoredMD5s' and is the empty-input sentinel
    -- under 'CreatorOptedOutOfVerification' (matching what
    -- canonical xdelta's @--noverify@ writes).
    toMD5Bytes = case xdelta1Verification patch of
      VerifyAgainstStoredMD5s md5Hash    -> md5Hash
      CreatorOptedOutOfVerification      -> xdelta1EmptyInputMD5Sentinel

-- | Encode the data-record's EDSIO source-record bytes. The wire
-- bytes here are all inline constants in the slap model: the name
-- is 'xdelta1DataRecordName', the MD5 is the data segment's MD5
-- (or the sentinel under 'CreatorOptedOutOfVerification'), the
-- length is the data segment's byte count, the kind byte is @1@
-- (data), and the offset-mode byte is @1@ (sequential). See
-- 'encodeControl' for why these are constants rather than fields
-- on 'XDelta1Patch'.
encodeDataRecord :: XDelta1Patch -> Builder
encodeDataRecord patch =
  putEdsioVarint (fromIntegral (ByteString.length xdelta1DataRecordName))
  <> byteString xdelta1DataRecordName
  <> byteString (unMD5Hash dataMD5Bytes)
  <> putEdsioVarint (fromIntegral (ByteString.length dataBytes))
  <> word8 1  -- kind: data record
  <> word8 1  -- offset-mode: sequential (slap's differ only emits sequential data)
  where
    dataBytes = xdelta1DataSegment patch
    dataMD5Bytes = case xdelta1Verification patch of
      VerifyAgainstStoredMD5s _     -> md5 dataBytes
      CreatorOptedOutOfVerification -> xdelta1EmptyInputMD5Sentinel

-- | Encode the source-file record's EDSIO source-record bytes from
-- the patch's flat @xdelta1Source*@ fields. The kind byte is @0@
-- (file source); the offset-mode byte tracks the differ's choice
-- ('xdelta1SourceOffsetMode'), which 'fixSequentialOffsets' on
-- parse and 'encodeInstruction' on create both consult to decide
-- whether per-instruction offsets are absolute or sequential.
encodeFileSourceRecord :: XDelta1Patch -> Builder
encodeFileSourceRecord patch =
  putEdsioVarint (fromIntegral (ByteString.length (xdelta1SourceName patch)))
  <> byteString (xdelta1SourceName patch)
  <> byteString (unMD5Hash sourceMD5Bytes)
  <> putEdsioVarint (fromIntegral (unFileSize (xdelta1SourceLength patch)))
  <> word8 0  -- kind: file source
  <> word8 (offsetModeByte (xdelta1SourceOffsetMode patch))
  where
    sourceMD5Bytes = case xdelta1SourceMD5 patch of
      Just md5Hash -> md5Hash
      Nothing      -> xdelta1EmptyInputMD5Sentinel

-- | Encode one instruction. The offset field is written as 0 when the
-- applicable source is in 'SequentialOffsets' mode (the parser at
-- 'Slap.XDelta1.Parse.fixSequentialOffsets' reconstructs the absolute
-- offset from the running cumulative length); under 'AbsoluteOffsets'
-- the offset is written verbatim. The applicable source is decided
-- by 'xdelta1InstructionTarget': data-targeting instructions are
-- always sequential (slap's differ only emits sequential data
-- emits, matching 'encodeDataRecord' above), file-targeting
-- instructions follow the patch's 'xdelta1SourceOffsetMode'.
encodeInstruction :: XDelta1Patch -> XDelta1Instruction -> Builder
encodeInstruction patch instruction =
  putEdsioVarint (instructionTargetWireIndex (xdelta1InstructionTarget instruction))
  <> offsetVarint
  <> putEdsioVarint (fromIntegral (unFileSize (xdelta1InstructionLength instruction)))
  where
    instructionOffsetMode = case xdelta1InstructionTarget instruction of
      FromDataSource -> SequentialOffsets
      FromFileSource -> xdelta1SourceOffsetMode patch
    offsetVarint = case instructionOffsetMode of
      SequentialOffsets -> putEdsioVarint 0
      AbsoluteOffsets   -> putEdsioVarint (fromIntegral (unOffset (xdelta1InstructionOffset instruction)))

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
