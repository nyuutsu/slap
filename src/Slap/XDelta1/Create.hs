{-# LANGUAGE OverloadedStrings #-}

-- | xdelta1 patch creation.
--
-- The wire encoder ('encodeXDelta1') is the round-trip partner of
-- 'Slap.XDelta1.Parse.parseControl' /
-- 'Slap.XDelta1.Parse.parseVersion1Point1': given an 'XDelta1Patch'
-- value, it produces wire bytes that 'Slap.XDelta1.Parse.parseXDelta1'
-- reads back to an equal patch (modulo gzip compression, which is
-- wire-optional). The 'createXDelta1' entry point chains a
-- (currently placeholder) differ that builds the patch value from
-- source and target bytes onto the encoder.
--
-- == Placeholder differ
--
-- The differ currently does the minimum work: the entire target
-- file becomes the data segment, and a single instruction tells
-- apply to copy the data segment into the output in one span.
-- The file source's MD5 + length are written to the patch's
-- control structure (canonical 'XDelta1DataAndFile' shape) but
-- the instruction stream never references it. The resulting
-- patch is wire-valid and applicable, just inefficient (roughly
-- target-sized). A future commit replaces the differ body with a
-- real algorithm that emits instructions referencing the file
-- source; the encoder below doesn't change.
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
-- The flag bit stays clear today. Real MD5s are computed and
-- written for the target, the data source, and the file source.
-- A future commit adds @slap create --no-verify@ which produces
-- 'CreatorOptedOutOfVerification' and writes sentinels.
module Slap.XDelta1.Create
  ( createXDelta1
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Sources(..)
    , XDelta1Instruction(..), XDelta1InstructionTarget(..)
    , XDelta1OffsetMode(..)
    , XDelta1SourceWireKind(..)
    , XDelta1VerificationPosture(..)
    , xdelta1EmptyInputMD5Sentinel
    )
import Slap.Binary (md5, word32BEBytes)
import Slap.Checksum (MD5Hash(..))
import Slap.Error (SlapError, CreateResult(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..),
                          PatchFileContents(..))
import Slap.Measure (Offset(..), FileSize(..), byteFileSize)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, byteString, toLazyByteString, word8)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.Word (Word8, Word32, Word64)

----------------------------------------------------------------------------
-- Top-level entry
----------------------------------------------------------------------------

-- | Create an xdelta1 patch from source and target bytes. Today
-- the differ is a placeholder: the entire target is stored inline
-- in the data segment, and a single instruction reconstructs the
-- output from it. The file source's MD5 and length are recorded
-- correctly so verification fires on apply; the file source bytes
-- aren't referenced by instructions until the real differ lands.
createXDelta1 :: InputFileContents -> OutputFileContents
              -> Either SlapError CreateResult
createXDelta1 (InputFileContents sourceBytes) (OutputFileContents targetBytes) =
  Right (CreateResult (PatchFileContents wireBytes) [])
  where
    patch     = buildPlaceholderPatch sourceBytes targetBytes
    wireBytes = encodeXDelta1 patch

----------------------------------------------------------------------------
-- Placeholder differ
----------------------------------------------------------------------------

-- | Construct an 'XDelta1Patch' value from source and target bytes
-- using the placeholder differ: the data segment IS the target,
-- one instruction copies it.
buildPlaceholderPatch :: ByteString -> ByteString -> XDelta1Patch
buildPlaceholderPatch sourceBytes targetBytes = XDelta1Patch
  { xdelta1FromName     = "source"
  , xdelta1ToName       = "target"
  , xdelta1Verification = VerifyAgainstStoredMD5s targetMD5
  , xdelta1TargetLength = targetFileSize
  , xdelta1Sources      = XDelta1Sources
      { xdelta1DataSource = XDelta1Source
          { xdelta1SourceName       = "(patch data)"
          , xdelta1SourceMD5        = Just dataSegmentMD5
          , xdelta1SourceLength     = targetFileSize
          , xdelta1SourceOffsetMode = AbsoluteOffsets
          }
      , xdelta1FileSource = XDelta1Source
          { xdelta1SourceName       = "source"
          , xdelta1SourceMD5        = Just sourceMD5
          , xdelta1SourceLength     = byteFileSize sourceBytes
          , xdelta1SourceOffsetMode = AbsoluteOffsets
          }
      }
  , xdelta1Instructions = [placeholderInstruction]
  , xdelta1DataSegment  = targetBytes
  }
  where
    targetFileSize = byteFileSize targetBytes
    targetMD5      = md5 targetBytes
    dataSegmentMD5 = targetMD5
    sourceMD5      = md5 sourceBytes
    placeholderInstruction = XDelta1Instruction
      { xdelta1InstructionTarget = FromDataSource
      , xdelta1InstructionOffset = Offset 0
      , xdelta1InstructionLength = targetFileSize
      }

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

    -- All four flag bits (0/1/2/3) stay clear: not opted out of
    -- verification, inputs aren't pre-compressed, patch isn't
    -- gzipped.
    flagsWord       = 0 :: Word32
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
    -- 'VerifyAgainstStoredMD5s'. Under
    -- 'CreatorOptedOutOfVerification' we'd write the empty-input
    -- sentinel here, but that path is gated on a CLI flag we
    -- don't add in this commit; today the posture is always
    -- 'VerifyAgainstStoredMD5s'.
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

----------------------------------------------------------------------------
-- EDSIO varint encoder
----------------------------------------------------------------------------

-- | Payload bits carried per byte.
edsioVarintBitsPerByte :: Int
edsioVarintBitsPerByte = 7

-- | Mask isolating the payload bits.
edsioVarintPayloadMask :: Word8
edsioVarintPayloadMask = 0x7F

-- | The continuation flag — high bit set when more bytes follow.
edsioVarintContinuationFlag :: Word8
edsioVarintContinuationFlag = 0x80

-- | Highest payload value that fits in a single byte's seven
-- payload bits. The number is the same as
-- 'edsioVarintPayloadMask', expressed at 'Word64' for use as a
-- threshold against the encoder's accumulator rather than as a
-- bit mask against a byte.
edsioVarintMaxSingleByteValue :: Word64
edsioVarintMaxSingleByteValue = fromIntegral edsioVarintPayloadMask

-- | Encode a non-negative integer as an EDSIO-style varint:
-- 7 payload bits per byte, LSB first, high bit set on every byte
-- except the last. Inverse of 'Slap.Get.edsioVarint'. Takes
-- 'Word64' under the same convention as 'Slap.Binary.putByuuVarint'
-- (caller's domain says non-negative; encoder doesn't redo the
-- check).
putEdsioVarint :: Word64 -> Builder
putEdsioVarint = writePayload
  where
    writePayload remainingBits
      | remainingBits <= edsioVarintMaxSingleByteValue =
          word8 (fromIntegral remainingBits)
      | otherwise =
          let thisBytePayload   = fromIntegral (remainingBits .&. fromIntegral edsioVarintPayloadMask) :: Word8
              thisByteWithFlag  = thisBytePayload .|. edsioVarintContinuationFlag
              bitsAfterThisByte = remainingBits `shiftR` edsioVarintBitsPerByte
          in word8 thisByteWithFlag <> writePayload bitsAfterThisByte
