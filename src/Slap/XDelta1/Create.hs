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
  , narrowXDelta1WireNumber
  ) where

import Slap.Compression.Stream (gzipDeflate)
import Slap.MetadataInclusion (VerificationInclusion(..), CompressionInclusion(..))
import Slap.XDelta1.FFI
    ( XDelta1DiffOutput(..)
    , xdelta1Diff
    )
import Slap.XDelta1.Types
    ( XDelta1Patch(..)
    , XDelta1SourceRoster(..), XDelta1FileSource(..)
    , rosterFileSource, rosterSourceCount, instructionTargetWireIndex
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

import Data.Bifunctor (first)
import Data.Foldable (traverse_)
import Data.Functor (void)
import Slap.Text (EncodedText,
                  encodedTextContent, encodedTextEncoding,
                  encodeTextLenient, encodeLossAdvisories)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, byteString, toLazyByteString, word8)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Bits (shiftL, (.|.))
import Data.Word (Word8, Word32)

----------------------------------------------------------------------------
-- Top-level entry
----------------------------------------------------------------------------

-- | Create an xdelta1 patch from source and target bytes.
-- The 'VerificationInclusion' and 'CompressionInclusion' choices gate the @FLAG_NO_VERIFY@ and @FLAG_PATCH_COMPRESSED@ wire effects;
-- see the module header.
createXDelta1 :: VerificationInclusion -> CompressionInclusion
              -> ResolvedXDelta1FileNames
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

-- | Wrap a 'XDelta1DiffOutput' into an 'XDelta1Patch' for the wire encoder,
-- deriving the source roster from which sources the instructions actually cite (see 'XDelta1SourceRoster').
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
  , xdelta1SourceRoster     = roster
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

    anyInstructionTargets wantedTarget =
      any ((== wantedTarget) . xdelta1InstructionTarget) (xdelta1DiffInstructions diff)

    fileSource = XDelta1FileSource
      { xdelta1FileSourceName       = resolvedXDelta1FromName resolvedNames
      , xdelta1FileSourceMD5        = perSourceMD5 (md5 sourceBytes)
      , xdelta1FileSourceLength     = byteFileSize sourceBytes
      , xdelta1FileSourceOffsetMode = xdelta1DiffFileSourceOffsetMode diff
      }

    roster = case (anyInstructionTargets FromDataSource, anyInstructionTargets FromFileSource) of
      (True,  True)  -> DataAndFileSources fileSource
      (True,  False) -> DataSourceOnly
      (False, True)  -> FileSourceOnly fileSource
      (False, False) -> NoSources

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
  refuseUnencodableWireNumbers patch
  controlOffsetWord <- narrowXDelta1WireNumber FieldXDelta1ControlOffset controlOffsetValue
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
      -- Source-record name and from-name are the same bytes, so the from-name's advisories speak for both;
      -- 'encodeFileSourceRecord' discards its own.
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

    controlOffsetValue :: Int
    controlOffsetValue =
      ByteString.length magicBytes
      + ByteString.length headerBytes
      + fromNameLength
      + toNameLength
      + ByteString.length dataSegment

-- | Narrow one of the format's wire integers to 32 bits, refusing anything past @0xFFFFFFFF@.
-- Every xdelta1 integer — offset, length, count — is a @guint32@:
-- the reference reads its EDSIO @uint@s back into one (@libedsio/default.c@ in @docs/xdelta1/upstream/xdelta-1.1.3.tar.gz@;
-- EDSIO itself can go wider, but the format never does), so a wider value could not be read back —
-- the reference would silently truncate it. slap declines to emit it, naming the field that overflowed.
narrowXDelta1WireNumber :: FieldName -> Int -> Either SlapError Word32
narrowXDelta1WireNumber field value =
  first NarrowingError (narrowToWord32 LabelXDelta1 field value)

-- | Before building any bytes, refuse any length past xdelta1's 32-bit wire space,
-- and any absolute-mode instruction offset (sequential offsets encode as zero).
-- Without this, a create over inputs of 4 GiB or more would emit varints slap's own parser could not read back — the EDSIO guint32 ceiling.
refuseUnencodableWireNumbers :: XDelta1Patch -> Either SlapError ()
refuseUnencodableWireNumbers patch = do
  void (narrowXDelta1WireNumber FieldXDelta1TargetLength
          (unFileSize (xdelta1TargetLength patch)))
  void (narrowXDelta1WireNumber FieldXDelta1DataSegmentLength
          (ByteString.length (xdelta1DataSegment patch)))
  traverse_ (narrowXDelta1WireNumber FieldXDelta1SourceLength . unFileSize . xdelta1FileSourceLength)
            (rosterFileSource (xdelta1SourceRoster patch))
  traverse_ checkInstructionWireNumbers (xdelta1Instructions patch)
  where
    checkInstructionWireNumbers instruction = do
      void (narrowXDelta1WireNumber FieldXDelta1InstructionLength
              (unFileSize (xdelta1InstructionLength instruction)))
      case instructionWireOffsetMode patch instruction of
        SequentialOffsets -> Right ()
        AbsoluteOffsets   ->
          void (narrowXDelta1WireNumber FieldXDelta1InstructionOffset
                  (unOffset (xdelta1InstructionOffset instruction)))

----------------------------------------------------------------------------
-- Control segment encoder
----------------------------------------------------------------------------

-- | Encode the EDSIO control structure, the mirror of 'Slap.XDelta1.Parse.parseControlBody'.
--
-- The two prelude words are load-bearing:
-- canonical's EDSIO reader (@libedsio\/generic.c:66@) bails with "Unregistered library: 0" if the type tag's low byte names no registered library,
-- and its allocation accountant (@libedsio\/default.c@) caps every reconstructed pointer at the declared bound.
-- An all-zeros prelude is refused even though it carries no instruction data.
encodeControl :: XDelta1Patch -> ByteString
encodeControl patch = LazyByteString.toStrict (toLazyByteString builder)
  where
    builder =
      byteString (word32BEBytes xdelta1ControlTypeTag)
      <> byteString (word32BEBytes xdelta1ControlAllocationBound)
      <> byteString (unMD5Hash toMD5Bytes)
      <> putEdsioVarint (fromIntegral (unFileSize (xdelta1TargetLength patch)))
      <> word8 hasDataByte
      <> putEdsioVarint (fromIntegral (rosterSourceCount roster))
      <> sourceRecords
      <> putEdsioVarint (fromIntegral (length instructions))
      <> foldMap (encodeInstruction patch) instructions

    instructions = xdelta1Instructions patch
    roster       = xdelta1SourceRoster patch

    sourceRecords = case roster of
      DataAndFileSources fileSource ->
        encodeDataRecord patch <> encodeFileSourceRecord fileSource
      DataSourceOnly            -> encodeDataRecord patch
      FileSourceOnly fileSource -> encodeFileSourceRecord fileSource
      NoSources                 -> mempty

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

encodeFileSourceRecord :: XDelta1FileSource -> Builder
encodeFileSourceRecord fileSource =
  putEdsioVarint (fromIntegral (ByteString.length sourceNameBytes))
  <> byteString sourceNameBytes
  <> byteString (unMD5Hash sourceMD5Bytes)
  <> putEdsioVarint (fromIntegral (unFileSize (xdelta1FileSourceLength fileSource)))
  <> word8 0  -- kind: file source
  <> word8 (offsetModeByte (xdelta1FileSourceOffsetMode fileSource))
  where
    -- The notice list is discarded: 'encodeXDelta1' already surfaced the same substitution advisories via the from-name slot.
    (sourceNameBytes, _notices) =
      encodeTextLenient (encodedTextEncoding sourceName)
                        (encodedTextContent sourceName)
    sourceName = unXDelta1FromName (xdelta1FileSourceName fileSource)
    sourceMD5Bytes = case xdelta1FileSourceMD5 fileSource of
      Just md5Hash -> md5Hash
      Nothing      -> xdelta1EmptyInputMD5Sentinel

-- | The offset field is written as 0 in 'SequentialOffsets' mode — the parser rebuilds the absolute offset from the running cumulative length —
-- and verbatim in 'AbsoluteOffsets'.
encodeInstruction :: XDelta1Patch -> XDelta1Instruction -> Builder
encodeInstruction patch instruction =
  putEdsioVarint (instructionTargetWireIndex (xdelta1SourceRoster patch) (xdelta1InstructionTarget instruction))
  <> offsetVarint
  <> putEdsioVarint (fromIntegral (unFileSize (xdelta1InstructionLength instruction)))
  where
    offsetVarint = case instructionWireOffsetMode patch instruction of
      SequentialOffsets -> putEdsioVarint 0
      AbsoluteOffsets   -> putEdsioVarint (fromIntegral (unOffset (xdelta1InstructionOffset instruction)))

-- | Data-targeting offsets are always sequential — slap's differ emits the data segment in citation order —
-- while file-targeting ones follow the file source's declared mode.
instructionWireOffsetMode :: XDelta1Patch -> XDelta1Instruction -> XDelta1OffsetMode
instructionWireOffsetMode patch instruction = case xdelta1InstructionTarget instruction of
  FromDataSource -> SequentialOffsets
  FromFileSource ->
    maybe AbsoluteOffsets xdelta1FileSourceOffsetMode
          (rosterFileSource (xdelta1SourceRoster patch))

-- | Wire byte for the offset-mode slot of an EDSIO source record.
-- Inverse of the parser's @offsetModeByte \/= 0@ test
-- ('Slap.XDelta1.Parse.parseOneSource').
offsetModeByte :: XDelta1OffsetMode -> Word8
offsetModeByte SequentialOffsets = 1
offsetModeByte AbsoluteOffsets   = 0

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
