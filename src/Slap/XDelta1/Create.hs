{-# LANGUAGE OverloadedStrings #-}

-- | xdelta1 patch creation.
--
-- The wire encoder ('encodeXDelta1') is the round-trip partner of 'Slap.XDelta1.Parse.parseControl' / 'Slap.XDelta1.Parse.parseVersion1Point1':
-- given an 'XDelta1Patch' value, it produces wire bytes that 'Slap.XDelta1.Parse.parseXDelta1' reads back to an equal patch.
-- 'createXDelta1' chains the differ in "Slap.XDelta1.FFI" onto the encoder;
-- this module owns the MD5s, the 'VerificationInclusion' wiring, the 'XDelta1PatchCompression' wiring, and 'XDelta1Patch' assembly.
--
-- == @FLAG_PATCH_COMPRESSED@
--
-- Gated by 'Slap.MetadataInclusion.CompressionInclusion', mapped onto the wire posture 'Slap.XDelta1.Types.XDelta1PatchCompression'.
-- Under 'CompressedPatch' (default) the bit is set and the data and control segments are gzip-deflated independently before placement;
-- under 'UncompressedPatch' (@slap create --no-compress@) the bit stays clear and the segments are emitted raw.
-- Both shapes are spec-conformant; canonical xdelta-1.x emits compressed by default.
--
-- == @FLAG_NO_VERIFY@
--
-- Gated by 'Slap.MetadataInclusion.VerificationInclusion'.
-- Under 'IncludeVerification' (default) the bit stays clear and real MD5s are written for the target, the data source, and the file source.
-- Under 'OmitVerification' (@slap create --omit-verification@) the bit is set and the posture is 'CreatorOptedOutOfVerification';
-- the sentinel ('xdelta1EmptyInputMD5Sentinel') fills every MD5 slot, matching what canonical xdelta's @--noverify@ produces.
module Slap.XDelta1.Create
  ( createXDelta1
  , narrowXDelta1ControlOffset
  ) where

import Slap.Compression.Stream (gzipDeflate)
import Slap.MetadataInclusion (VerificationInclusion(..), CompressionInclusion(..))
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
    , XDelta1FromName(..)
    , XDelta1ToName(..)
    , ResolvedXDelta1FileNames
    , resolvedXDelta1FromName
    , resolvedXDelta1ToName
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
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Narrow (narrowToWord32)
import Slap.Status (SlapError(..), SlapAdvisory, CreateResult(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..),
                          PatchFileContents(..))
import Slap.Measure (Offset(..), FileSize(..), byteFileSize)
import Slap.Text (EncodedText,
                  encodedTextContent, encodedTextEncoding,
                  encodeTextLenient, encodeLossAdvisories)

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
-- The 'VerificationInclusion' and 'CompressionInclusion' choices gate the @FLAG_NO_VERIFY@ and @FLAG_PATCH_COMPRESSED@ wire effects;
-- see the module header.
createXDelta1 :: VerificationInclusion -> CompressionInclusion
              -> ResolvedXDelta1FileNames
                 -- ^ from-name and to-name, already resolved and cap-checked by the porcelain
                 -- via 'Slap.XDelta1.Types.resolveXDelta1FileNames' / 'Slap.XDelta1.Types.requireXDelta1FileNames'.
                 -- Those two are the only constructors, so this function writes the names without re-checking
                 -- (both bytes locale-encoded, each ≤ the u16 cap).
              -> InputFileContents -> OutputFileContents
              -> Either SlapError CreateResult
createXDelta1 verificationChoice compressionChoice resolvedNames inputContents outputContents = do
  diff <- xdelta1Diff inputContents outputContents
  let sourceBytes = unInputFileContents inputContents
      targetBytes = unOutputFileContents outputContents
      patchCompression = case compressionChoice of
        IncludeCompression -> CompressedPatch
        OmitCompression    -> UncompressedPatch
      patch = assemblePatch verificationChoice patchCompression resolvedNames
                            sourceBytes targetBytes diff
  (wireBytes, nameAdvisories) <- encodeXDelta1 patch
  Right (CreateResult (PatchFileContents wireBytes) nameAdvisories)

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
  -> ResolvedXDelta1FileNames
  -> ByteString -> ByteString
     -- ^ source bytes and target bytes (for MD5 and size).
  -> XDelta1DiffOutput -> XDelta1Patch
assemblePatch inclusion compression resolvedNames sourceBytes targetBytes diff = XDelta1Patch
  { xdelta1FromName         = resolvedXDelta1FromName resolvedNames
  , xdelta1ToName           = resolvedXDelta1ToName   resolvedNames
  , xdelta1Verification     = verificationPosture
  , xdelta1PatchCompression = compression
    -- Slap doesn't detect gzip-magic on inputs at create time, so
    -- both inputs are recorded as raw bytes.
  , xdelta1FromAtDeltaTime  = FileWasRawBytes
  , xdelta1ToAtDeltaTime    = FileWasRawBytes
  , xdelta1TargetLength     = byteFileSize targetBytes
    -- The per-source-record name in the EDSIO source list reflects
    -- the same source file as the header's from-name; the resolver
    -- produces one value and both wire fields consume it.
  , xdelta1SourceName       = resolvedXDelta1FromName resolvedNames
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
encodeXDelta1 :: XDelta1Patch -> Either SlapError (ByteString, [SlapAdvisory])
encodeXDelta1 patch = do
  controlOffsetWord <- narrowXDelta1ControlOffset controlOffsetValue
  Right
    ( ByteString.concat
        [ magicBytes
        , headerBytes
        , fromNameBytes
        , toNameBytes
        , dataSegment
        , controlSegment
        , word32BEBytes controlOffsetWord
        , magicBytes
        ]
    , fromNameAdvisories ++ toNameAdvisories
      -- The source-record name shares its bytes with the from-name
      -- ('assemblePatch' pipes one value into both), so the from-name's
      -- advisories speak for both; 'encodeFileSourceRecord' discards its own.
    )
  where
    magicBytes     = "%XDZ004%"
    (fromNameBytes, fromNameAdvisories) =
      encodeXDelta1Name FieldXDelta1FromName (unXDelta1FromName (xdelta1FromName patch))
    (toNameBytes, toNameAdvisories) =
      encodeXDelta1Name FieldXDelta1ToName   (unXDelta1ToName   (xdelta1ToName   patch))
    fromNameLength = ByteString.length fromNameBytes
    toNameLength   = ByteString.length toNameBytes

    -- Flags word: @FLAG_NO_VERIFY@ (bit 0) tracks the patch's verification posture;
    -- @FLAG_FROM_COMPRESSED@ (bit 1) and @FLAG_TO_COMPRESSED@ (bit 2) track whether the from- or to-file was a gzip stream at delta time
    -- (slap never sets these two at create, but carries them through from parsed patches under convert, so a round-trip preserves them);
    -- @FLAG_PATCH_COMPRESSED@ (bit 3) tracks the patch's compression posture.
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

    -- File offset where the control segment begins. Narrowed to the
    -- trailer's 4-byte field by 'narrowXDelta1ControlOffset' rather
    -- than masked, so a patch too large for xdelta1's 32-bit positions
    -- is refused, not silently truncated.
    controlOffsetValue :: Int
    controlOffsetValue =
      ByteString.length magicBytes
      + ByteString.length headerBytes
      + fromNameLength
      + toNameLength
      + ByteString.length dataSegment

-- | Narrow a control-segment file offset to the trailer's 4-byte
-- big-endian field, refusing a value past @0xFFFFFFFF@. xdelta1's
-- positions are 32-bit — the format reconstructs its EDSIO @uint@s
-- into a @guint32@ and the reference documents a 32-bit file-size
-- limit (the underlying EDSIO library can serialise wider, but the
-- xdelta1 format does not draw on that) — so a patch whose control
-- offset would not fit cannot be read back faithfully: the reference
-- would silently truncate the trailer pointer. slap declines to emit
-- it instead, the create-side mirror of the parser's guint32 cap.
narrowXDelta1ControlOffset :: Int -> Either SlapError Word32
narrowXDelta1ControlOffset value =
  case narrowToWord32 LabelXDelta1 FieldXDelta1ControlOffset value of
    Left  failure -> Left (NarrowingError failure)
    Right word    -> Right word

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
-- The two prelude words are non-negotiable:
-- canonical xdelta's generic EDSIO reader (@libedsio\/generic.c:66@) bails immediately with "Unregistered library: 0"
-- when the type tag's low byte isn't a registered library number,
-- and its sub-allocation accountant (@libedsio\/default.c@) caps every reconstructed pointer at the declared allocation bound.
-- An all-zeros prelude is therefore rejected by canonical even though it carries no instruction data.
--
-- The data-record's wire bytes don't live on 'XDelta1Patch': 'encodeDataRecord' derives them from the data-segment bytes
-- and 'xdelta1DataRecordName'. The source-file record's bytes come from the patch's flat @xdelta1Source*@ fields.
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

-- | Encode the data-record's EDSIO source-record bytes;
-- see 'encodeControl' for why these are inline constants rather than fields on 'XDelta1Patch'.
encodeDataRecord :: XDelta1Patch -> Builder
encodeDataRecord patch =
  putEdsioVarint (fromIntegral (ByteString.length xdelta1DataRecordName))
  <> byteString xdelta1DataRecordName
  <> byteString (unMD5Hash dataMD5Bytes)
  <> putEdsioVarint (fromIntegral (ByteString.length dataBytes))
  <> word8 1  -- kind: data record
  <> word8 (offsetModeByte SequentialOffsets)  -- slap's differ only emits sequential data
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
  putEdsioVarint (fromIntegral (ByteString.length sourceNameBytes))
  <> byteString sourceNameBytes
  <> byteString (unMD5Hash sourceMD5Bytes)
  <> putEdsioVarint (fromIntegral (unFileSize (xdelta1SourceLength patch)))
  <> word8 0  -- kind: file source
  <> word8 (offsetModeByte (xdelta1SourceOffsetMode patch))
  where
    -- The notice list is discarded: 'encodeXDelta1' already surfaced the same substitution advisories via the from-name slot.
    (sourceNameBytes, _notices) =
      encodeTextLenient (encodedTextEncoding sourceName)
                        (encodedTextContent sourceName)
    sourceName = unXDelta1FromName (xdelta1SourceName patch)
    sourceMD5Bytes = case xdelta1SourceMD5 patch of
      Just md5Hash -> md5Hash
      Nothing      -> xdelta1EmptyInputMD5Sentinel

-- | Encode one instruction. The offset field is written as 0 when the
-- applicable source is in 'SequentialOffsets' mode (the parser at
-- 'Slap.XDelta1.Parse.fixSequentialOffsets' reconstructs the absolute
-- offset from the running cumulative length); under 'AbsoluteOffsets'
-- the offset is written verbatim. The applicable source is decided
-- by 'xdelta1InstructionTarget': data-targeting instructions are
-- always sequential, file-targeting instructions follow the patch's
-- 'xdelta1SourceOffsetMode'.
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

-- | Re-encode an xdelta1 header name from its typed 'EncodedText' to
-- the wire bytes that go between the header and the data segment.
-- Lenient: codepoints the target encoding can't represent become
-- the encoding's substitute character and surface as a single
-- 'FieldEncodedSubstituted' advisory carrying the substitution
-- count. The byte length is not re-checked here; the resolver in
-- "Slap.XDelta1.Types" cap-checks the lenient-encoded byte count at
-- construction of 'ResolvedXDelta1FileNames', so by the time
-- 'encodeXDelta1' runs the bytes are known to fit the u16 slot.
encodeXDelta1Name :: FieldName -> EncodedText -> (ByteString, [SlapAdvisory])
encodeXDelta1Name field text =
  let (bytes, notices) = encodeTextLenient (encodedTextEncoding text)
                                           (encodedTextContent text)
  in (bytes, encodeLossAdvisories LabelXDelta1 field notices)
