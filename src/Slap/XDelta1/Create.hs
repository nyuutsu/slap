{-# LANGUAGE OverloadedStrings #-}

-- | xdelta1 patch creation.
--
-- The wire encoder ('encodeXDelta1') is the round-trip partner of
-- 'Slap.XDelta1.Parse.parseControl' /
-- 'Slap.XDelta1.Parse.parseVersion1Point1': given an 'XDelta1Patch'
-- value, it produces wire bytes that 'Slap.XDelta1.Parse.parseXDelta1'
-- reads back to an equal patch (modulo gzip compression, which is
-- wire-optional). 'createXDelta1' chains the rsync-style differ in
-- "Slap.XDelta1.FFI" (kernel in @rusty-slap\/src\/xdelta1_diff.rs@)
-- onto the encoder: the differ owns the rolling-checksum index over
-- source, the byte-by-byte target walk, and the per-source
-- sequential-mode tracking; this module owns the MD5s, the
-- 'VerificationInclusion' wiring, and 'XDelta1Patch' assembly.
--
-- == @FLAG_PATCH_COMPRESSED@
--
-- The flag bit stays clear today. Slap has 'gzipInflate' (Rust
-- FFI) but no 'gzipDeflate'; uncompressed @%XDZ004%@ patches are
-- spec-conformant. A future commit adds 'gzipDeflate' to
-- "Slap.Compression.Stream" and gates the bit on user request.
--
-- == @FLAG_NO_VERIFY@
--
-- Gated by 'Slap.Convert.VerificationInclusion', threaded in from
-- the porcelain. Under 'IncludeVerification' (default) the bit
-- stays clear, real MD5s are computed and written for the target,
-- the data source, and the file source. Under 'OmitVerification'
-- (set by @slap create --no-verify@) the bit is set, the patch's
-- verification posture is 'CreatorOptedOutOfVerification', and the
-- sentinel ('xdelta1EmptyInputMD5Sentinel') is written into every
-- MD5 slot — matching what canonical xdelta's @--noverify@
-- produces.
module Slap.XDelta1.Create
  ( createXDelta1
  , xdelta1FlagNoVerify
  ) where

import Slap.MetadataInclusion (VerificationInclusion(..))
import Slap.XDelta1.FFI
    ( XDelta1DiffOutput(..)
    , rustyXDelta1Diff
    )
import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Sources(..)
    , XDelta1Instruction(..), XDelta1InstructionTarget(..)
    , XDelta1OffsetMode(..)
    , XDelta1SourceWireKind(..)
    , XDelta1VerificationPosture(..)
    , xdelta1EmptyInputMD5Sentinel
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
-- ('Slap.XDelta1.FFI.rustyXDelta1Diff') produces the instruction
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
createXDelta1 :: VerificationInclusion -> InputFileContents -> OutputFileContents
              -> Either SlapError CreateResult
createXDelta1 inclusion inputContents outputContents =
  case rustyXDelta1Diff inputContents outputContents of
    Left slapError -> Left slapError
    Right diff ->
      let sourceBytes = unInputFileContents inputContents
          targetBytes = unOutputFileContents outputContents
          patch       = assemblePatch inclusion sourceBytes targetBytes diff
          wireBytes   = encodeXDelta1 patch
      in  Right (CreateResult (PatchFileContents wireBytes) [])

----------------------------------------------------------------------------
-- Differ output → XDelta1Patch
----------------------------------------------------------------------------

-- | Wrap a 'XDelta1DiffOutput' (instructions + data segment + the
-- per-source sequential-mode flags) into an 'XDelta1Patch' ready
-- for the wire encoder. The MD5s and 'VerificationInclusion' wiring
-- live here; the differ doesn't know about them.
assemblePatch
  :: VerificationInclusion -> ByteString -> ByteString
  -> XDelta1DiffOutput -> XDelta1Patch
assemblePatch inclusion sourceBytes targetBytes diff = XDelta1Patch
  { xdelta1FromName     = "source"
  , xdelta1ToName       = "target"
  , xdelta1Verification = verificationPosture
  , xdelta1TargetLength = byteFileSize targetBytes
  , xdelta1Sources      = XDelta1Sources
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
  , xdelta1Instructions = xdelta1DiffInstructions diff
  , xdelta1DataSegment  = dataSegmentBytes
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
-- 'Slap.XDelta1.Parse.parseVersion1Point1' for the
-- 'Slap.XDelta1.Parse.NoVerifyFlagClear' / uncompressed case:
-- produces a @%XDZ004%@ patch that
-- 'Slap.XDelta1.Parse.parseXDelta1' reads back to an equal patch.
--
-- Layout:
--
--   1. Magic prefix:        @%XDZ004%@ (8 bytes)
--   2. Header words:        6 × uint32 BE (flags, name lengths,
--                           4 reserved zero words)
--   3. From-name bytes
--   4. To-name bytes
--   5. Data segment         (uncompressed, no @FLAG_PATCH_COMPRESSED@)
--   6. Control segment      (EDSIO-serialized @XdeltaControl@)
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

    -- @FLAG_NO_VERIFY@ tracks the patch's verification posture;
    -- the other three flag bits (1/2/3 — input pre-compression and
    -- gzip-of-patch) stay clear: slap doesn't deflate or declare
    -- the inputs were pre-compressed.
    flagsWord = case xdelta1Verification patch of
      VerifyAgainstStoredMD5s _     -> 0
      CreatorOptedOutOfVerification -> xdelta1FlagNoVerify
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

    dataSegment    = xdelta1DataSegment patch
    controlSegment = encodeControl patch

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
-- 'Slap.XDelta1.Parse.parseControlBody'): 8 zero bytes for the
-- deprecated type-tag + allocation slot, the target MD5, a varint
-- target length, the @has_data@ boolean, the source list (always
-- two records, in @[data, file]@ order), and the instruction list.
encodeControl :: XDelta1Patch -> ByteString
encodeControl patch = LazyByteString.toStrict (toLazyByteString builder)
  where
    builder =
      byteString (ByteString.replicate 8 0)
      <> byteString (unMD5Hash toMD5Bytes)
      <> putEdsioVarint (fromIntegral (unFileSize (xdelta1TargetLength patch)))
      <> word8 1  -- has_data flag: nonzero means a data segment follows
      <> putEdsioVarint 2  -- two source records: the data source, then the file source
      <> encodeSource (xdelta1DataSource sources) WireKindData
      <> encodeSource (xdelta1FileSource sources) WireKindFile
      <> putEdsioVarint (fromIntegral (length instructions))
      <> foldMap encodeInstruction instructions

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

encodeInstruction :: XDelta1Instruction -> Builder
encodeInstruction instruction =
  putEdsioVarint (instructionTargetWireIndex (xdelta1InstructionTarget instruction))
  <> putEdsioVarint (fromIntegral (unOffset (xdelta1InstructionOffset instruction)))
  <> putEdsioVarint (fromIntegral (unFileSize (xdelta1InstructionLength instruction)))

-- | Wire flag-bit value for @FLAG_NO_VERIFY@ (bit 0 of the
-- xdelta1 header's first 32-bit flag word). Set when the patch
-- declares 'CreatorOptedOutOfVerification'.
xdelta1FlagNoVerify :: Word32
xdelta1FlagNoVerify = 1

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
