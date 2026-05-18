{-# LANGUAGE OverloadedStrings #-}

module Slap.XDelta1.Parse
  ( parseXDelta1
  , parseVersion1Point1
  , parseControl
  , parseOneSource
  , parseInstructions
  , requireDataAndFileRecords
  , translateInstruction
  , fixSequentialOffsets
    -- * Role newtypes for parseControl arguments
  , XDelta1ControlSegment(..)
  , XDelta1DataSegment(..)
  , XDelta1NoVerifyFlag(..)
  ) where

-- Canonical reference: tools/xdelta1/xdelta-1.1.4/ (xdelta 1.x source)

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Instruction(..)
    , XDelta1InstructionTarget(..)
    , XDelta1OffsetMode(..)
    , XDelta1VerificationPosture(..)
    , XDelta1PatchCompression(..)
    , XDelta1FileAtDeltaTime(..)
    , XDelta1FromName(..)
    , XDelta1ToName(..)
    , xdelta1TrailerSize
    , xdelta1EmptyInputMD5Sentinel
    , xdelta1DataRecordName
    , xdelta1FlagNoVerify
    , xdelta1FlagFromCompressed
    , xdelta1FlagToCompressed
    , xdelta1FlagPatchCompressed
    , xdelta1ControlTypeTag
    )
import Slap.Binary (getWord32BE, md5)
import Slap.Checksum (MD5Hash(..))
import Slap.Status (SlapError(..), DecompressionFailure(..), Parsed(..),
                    SlapAdvisory(..),
                    XDelta1KnownUnsupportedVersion(..),
                    XDelta1ShapeViolation(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runByteParser, getByte, getBytes, skip, edsioVarint, word32BE)
import Slap.Measure (Length(..), FileSize(..), Offset(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ExpectedMagic(..),
                     ExpectedSize(..), ActualSize(..), byteLength)
import Slap.Compression.Stream (gzipInflate)

import Control.Monad (unless)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), shiftR)
import Data.Int (Int64)
import Numeric (showHex)

----------------------------------------------------------------------------
-- Role newtypes for 'parseControl'
----------------------------------------------------------------------------

-- | Decompressed control segment of an XDelta1 patch — the EDSIO-
-- serialized record stream consumed by 'parseControl'. Distinct
-- from 'XDelta1DataSegment' so the two cannot be transposed at the
-- 'parseControl' call site.
newtype XDelta1ControlSegment = XDelta1ControlSegment
  { unXDelta1ControlSegment :: ByteString
  } deriving (Eq, Show)

-- | Decompressed data segment of an XDelta1 patch — the
-- XdeltaData payload referenced by individual instructions in the
-- control stream.
newtype XDelta1DataSegment = XDelta1DataSegment
  { unXDelta1DataSegment :: ByteString
  } deriving (Eq, Show)

-- | Whether bit 0 (@FLAG_NO_VERIFY@) of the patch header's flags
-- word was set. Threaded from 'parseVersion1Point1' (where the
-- flags word is read) into 'parseControl' (which decides how to
-- wrap parsed MD5 values: under 'NoVerifyFlagSet', target MD5
-- goes into 'CreatorOptedOutOfVerification' and per-source MD5s
-- become 'Nothing'; under 'NoVerifyFlagClear', target MD5 goes
-- into 'VerifyAgainstStoredMD5s' and per-source MD5s become
-- 'Just').
data XDelta1NoVerifyFlag
  = NoVerifyFlagClear
  | NoVerifyFlagSet
  deriving (Show, Eq)

-- | The two values the wire format's source-kind byte can carry.
-- Parser-internal: the wire records its source-kind on a per-record
-- basis (the byte is @1@ for the data record and @0@ for the file
-- record), and 'requireDataAndFileRecords' uses these tags to
-- validate the canonical @[data, file]@ ordering before the parser
-- narrows the records into 'XDelta1Patch' fields. Canonical xdelta's
-- @xdelta.c:246@ writes the data source at index 0 with kind byte
-- 1; @xdmain.c:1539-1542@ writes the from-file source at index 1
-- with kind byte 0. Not part of slap's in-memory model — the data
-- source isn't a source in any user-meaningful sense (see
-- "Slap.XDelta1.Types" for the rationale).
data ParsedSourceKind
  = ParsedDataKind
  | ParsedFileKind
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseXDelta1 :: PatchFileContents -> Either SlapError (Parsed XDelta1Patch)
parseXDelta1 patchContents@(PatchFileContents input)
  | ByteString.length input < 20 = Left (InputTooShort LabelXDelta1 (RequiredLength (Length 20)) (ActualLength (byteLength input)))
  | magic == "%XDZ004%" = parseVersion1Point1 patchContents (ExpectedMagic magic)
  | magic == "%XDZ003%" = Left (UnsupportedXDelta1Subformat XDelta1_1_0_4)
  | magic == "%XDZ002%" = Left (UnsupportedXDelta1Subformat XDelta1_1_0)
  | ByteString.take 7 input == "%XDELTA" = Left (UnsupportedXDelta1Subformat XDelta1_0_14)
  | otherwise = Left (BadMagic LabelXDelta1 (ActualMagic (ByteString.take 8 input)))
  where
    magic = ByteString.take 8 input

-- | Body parser for @%XDZ004%@ (xdelta 1.1.x), the only xdelta1 era
-- slap currently supports. Sibling body parsers for other eras
-- (1.0.4 under @%XDZ003%@, 1.0.x under @%XDZ002%@) would live
-- alongside this one and be dispatched to by 'parseXDelta1'.
parseVersion1Point1 :: PatchFileContents -> ExpectedMagic -> Either SlapError (Parsed XDelta1Patch)
parseVersion1Point1 (PatchFileContents input) expectedMagic
  | totalLength < 44 = Left (InputTooShort LabelXDelta1 (RequiredLength (Length 44)) (ActualLength (Length totalLength)))
  | trailingMagic /= unExpectedMagic expectedMagic = Left (TrailingMagicMismatch LabelXDelta1 expectedMagic (ActualMagic trailingMagic))
  | otherwise = do
      decompressedData    <- safeDecompressGZip dataSegmentRaw
      decompressedControl <- safeDecompressGZip controlSegmentRaw
      Parsed patch warnings <-
        parseControl noVerifyFlag
                     compressionPosture
                     (XDelta1ControlSegment decompressedControl)
                     (XDelta1DataSegment    decompressedData)
                     (XDelta1FromName       fromName)
                     (XDelta1ToName         toName)
      Right (Parsed (recordInputPreCompression patch) warnings)
  where
    -- | Bits 1 and 2 of the flags word record whether the canonical
    -- tool transparently decompressed gzip-magic input files at
    -- delta time. They're header-derived, not control-derived, so
    -- 'parseControl' (which is scoped to the control segment) is
    -- not the right home for them — we set them on the patch after
    -- the control parse returns.
    recordInputPreCompression patch = patch
      { xdelta1FromAtDeltaTime = fromAtDeltaTime
      , xdelta1ToAtDeltaTime   = toAtDeltaTime
      }
    fromAtDeltaTime = if flags .&. xdelta1FlagFromCompressed /= 0
                        then FileWasGzipStream
                        else FileWasRawBytes
    toAtDeltaTime   = if flags .&. xdelta1FlagToCompressed /= 0
                        then FileWasGzipStream
                        else FileWasRawBytes

    totalLength = ByteString.length input

    -- Header: 6 x uint32 BE at offset 8
    flags    = getWord32BE 8 input
    nameLengths = getWord32BE 12 input
    fromNameLength = fromIntegral (nameLengths `shiftR` 16) :: Int
    toNameLength   = fromIntegral (nameLengths .&. 0xFFFF) :: Int
    fromName = ByteString.take fromNameLength (ByteString.drop 32 input)
    toName   = ByteString.take toNameLength (ByteString.drop (32 + fromNameLength) input)
    headerOffset = 32 + fromNameLength + toNameLength

    -- Trailer: last 12 bytes = control_offset (4B) + magic (8B)
    trailerOffset = totalLength - xdelta1TrailerSize
    controlOffset = fromIntegral (getWord32BE trailerOffset input) :: Int
    trailingMagic = ByteString.take 8 (ByteString.drop (totalLength - 8) input)

    -- Decompress segments if FLAG_PATCH_COMPRESSED (bit 3)
    compressed   = flags .&. xdelta1FlagPatchCompressed /= 0
    compressionPosture = if compressed then CompressedPatch else UncompressedPatch
    noVerifyFlag = if flags .&. xdelta1FlagNoVerify /= 0
                     then NoVerifyFlagSet
                     else NoVerifyFlagClear
    dataSegmentRaw = ByteString.take (controlOffset - headerOffset) (ByteString.drop headerOffset input)
    controlSegmentRaw = ByteString.take (trailerOffset - controlOffset) (ByteString.drop controlOffset input)

    safeDecompressGZip raw
      | not compressed = Right raw
      | ByteString.null raw    = Right ByteString.empty
      | otherwise      = case gzipInflate raw of
          Left cause   -> Left (DecompressionFailed (XDelta1Failed cause))
          Right result -> Right result

-- | An xdelta1 source record as parsed from the wire, before the
-- patch-level verification posture has been folded into its MD5
-- representation and before the @[data, file]@ shape has been
-- validated. 'parsedSourceKind' captures the wire's source-kind
-- byte so 'requireDataAndFileRecords' can verify the canonical
-- ordering and refuse anything else. Internal to the parser; not
-- exported.
data ParsedSourceRecord = ParsedSourceRecord
  { parsedSourceName       :: !ByteString
  , parsedSourceMD5        :: !MD5Hash
  , parsedSourceLength     :: !FileSize
  , parsedSourceKind       :: !ParsedSourceKind
  , parsedSourceOffsetMode :: !XDelta1OffsetMode
  } deriving (Show, Eq)

-- | The two records that survive shape validation, in canonical
-- @[data, file]@ order. Carries the pre-posture-folding records so
-- the parser can fold the verification posture in per-side and the
-- curio-warning check can consult the raw MD5s. Internal to the
-- parser; not exported.
data ParsedSourcePair = ParsedSourcePair
  { parsedDataRecord :: !ParsedSourceRecord
  , parsedFileRecord :: !ParsedSourceRecord
  } deriving (Show, Eq)

-- | An xdelta1 instruction as parsed from the wire — the source-
-- index is the raw 'Int64' from the EDSIO varint; 'translateInstruction'
-- translates it to 'XDelta1InstructionTarget' and refuses indices
-- outside @{0, 1}@. Internal to the parser; not exported.
data ParsedInstruction = ParsedInstruction
  { parsedInstructionWireIndex :: !Int64
  , parsedInstructionOffset    :: !Offset
  , parsedInstructionLength    :: !FileSize
  } deriving (Show, Eq)

-- | Parse the EDSIO-serialized XdeltaControl from the control segment.
-- The source list is parsed raw and then narrowed to the canonical
-- @[data, file]@ pair by 'requireDataAndFileRecords'; any other count
-- or ordering is rejected with 'UnsupportedXDelta1Shape' before the
-- patch record is constructed. Instructions are parsed against a
-- wider 'ParsedInstruction' intermediate and then translated by
-- 'translateInstruction'; wire indices outside @{0, 1}@ are rejected
-- with 'XDelta1UnknownInstructionTarget'. Only after both checks
-- pass do sequential offsets get resolved and the 'XDelta1Patch'
-- record assembled.
--
-- The data-record's wire fields are handled per-field rather than
-- carried on the patch (see "Slap.XDelta1.Types" for the rationale):
--
--   [@name@]        Compared to 'xdelta1DataRecordName'. Mismatches
--                   surface an informational notice
--                   ('XDelta1DataRecordNameDiverges') — the field is
--                   a display label and canonical xdelta-1.x never
--                   gates apply on it.
--   [@MD5@]         Under 'VerifyAgainstStoredMD5s', compared to the
--                   MD5 of the data-segment bytes via the porcelain's
--                   verification pipeline ('verifyDataMD5'); under
--                   'CreatorOptedOutOfVerification', the bytes are
--                   discarded (the curio-warning consults them
--                   separately to spot non-canonical sentinels).
--   [@length@]      Compared to the byte count of the data segment
--                   slap parsed from the patch envelope; structural
--                   inconsistency is fatal
--                   ('XDelta1DataRecordLengthMismatch').
--   [@offset-mode@] Dispatches parser behavior for data-targeting
--                   instructions: under 'SequentialOffsets', their
--                   wire offsets are zero and the absolute offset is
--                   reconstructed by 'fixSequentialOffsets'; under
--                   'AbsoluteOffsets', the wire offset is used
--                   verbatim. Canonical's converter (xdelta.c:1433-
--                   1471) can produce absolute-mode data records, so
--                   the parser must honor both.
--
-- All xdelta1 parse warnings are emitted here: the family
-- 'VerificationOptedOutByCreator' under 'NoVerifyFlagSet', and the
-- 'XDelta1NoVerifyWithDivergentSentinel' curio when the flag is set
-- but the stored MD5 slots do not match 'xdelta1EmptyInputMD5Sentinel'.
parseControl :: XDelta1NoVerifyFlag
             -> XDelta1PatchCompression
             -> XDelta1ControlSegment
             -> XDelta1DataSegment
             -> XDelta1FromName
             -> XDelta1ToName
             -> Either SlapError (Parsed XDelta1Patch)
parseControl noVerifyFlag compressionPosture controlSegment dataSegment fromName toName
  | ByteString.length controlBytes < 28 =
      Left (TruncatedRecord LabelXDelta1 0 (Length 28) (byteLength controlBytes))
  | otherwise = do
      (toMD5, targetLength, parsedSources, parsedInstrs) <-
        case runByteParser parseControlBody controlBytes of
          Left parserError -> Left (ParseError LabelXDelta1 parserError)
          Right result      -> Right result
      sourcePair <- requireDataAndFileRecords parsedSources
      let parsedDataRec      = parsedDataRecord sourcePair
          parsedFileRec      = parsedFileRecord sourcePair
          dataSegmentLength  = ByteString.length dataBytes
          declaredDataLength = parsedSourceLength parsedDataRec
      unless (fromIntegral (unFileSize declaredDataLength) == dataSegmentLength) $
        Left $ XDelta1DataRecordLengthMismatch
          (ExpectedSize declaredDataLength)
          (ActualSize (FileSize dataSegmentLength))
      let verificationPosture = case noVerifyFlag of
            NoVerifyFlagSet   -> CreatorOptedOutOfVerification
            NoVerifyFlagClear -> VerifyAgainstStoredMD5s toMD5
          fileSourceMD5 = case verificationPosture of
            VerifyAgainstStoredMD5s _     -> Just (parsedSourceMD5 parsedFileRec)
            CreatorOptedOutOfVerification -> Nothing
          dataOffsetMode = parsedSourceOffsetMode parsedDataRec
          fileOffsetMode = parsedSourceOffsetMode parsedFileRec
      case verificationPosture of
        CreatorOptedOutOfVerification -> Right ()
        VerifyAgainstStoredMD5s _     ->
          let computedDataMD5 = md5 dataBytes
              declaredDataMD5 = parsedSourceMD5 parsedDataRec
          in unless (computedDataMD5 == declaredDataMD5) $
               Left $ XDelta1DataRecordMD5Mismatch declaredDataMD5 computedDataMD5
      translatedInstructions <- traverse translateInstruction parsedInstrs
      let fixedInstructions =
            fixSequentialOffsets dataOffsetMode fileOffsetMode translatedInstructions
          patch = XDelta1Patch
            { xdelta1FromName         = fromName
            , xdelta1ToName           = toName
            , xdelta1Verification     = verificationPosture
            , xdelta1PatchCompression = compressionPosture
              -- 'parseControl' is scoped to the control segment;
              -- bits 1/2 of the header flags word are not in scope
              -- here. 'parseVersion1Point1' overrides both fields
              -- after the parse returns. Tests that drive
              -- 'parseControl' directly see the defaults.
            , xdelta1FromAtDeltaTime  = FileWasRawBytes
            , xdelta1ToAtDeltaTime    = FileWasRawBytes
            , xdelta1TargetLength     = targetLength
            , xdelta1SourceName       = XDelta1FromName (parsedSourceName parsedFileRec)
            , xdelta1SourceMD5        = fileSourceMD5
            , xdelta1SourceLength     = parsedSourceLength parsedFileRec
            , xdelta1SourceOffsetMode = fileOffsetMode
            , xdelta1Instructions     = fixedInstructions
            , xdelta1DataSegment      = dataBytes
            }
          dataNameNotices
            | parsedSourceName parsedDataRec == xdelta1DataRecordName = []
            | otherwise =
                [XDelta1DataRecordNameDiverges (parsedSourceName parsedDataRec)]
          postureWarnings = case verificationPosture of
            VerifyAgainstStoredMD5s _      -> []
            CreatorOptedOutOfVerification  -> [VerificationOptedOutByCreator LabelXDelta1]
          curioWarnings = case noVerifyFlag of
            NoVerifyFlagClear -> []
            NoVerifyFlagSet
              | all (== xdelta1EmptyInputMD5Sentinel)
                    [ toMD5
                    , parsedSourceMD5 parsedDataRec
                    , parsedSourceMD5 parsedFileRec
                    ]
                  -> []
              | otherwise
                  -> [XDelta1NoVerifyWithDivergentSentinel]
      Right (Parsed patch (dataNameNotices ++ postureWarnings ++ curioWarnings))
  where
    controlBytes  = unXDelta1ControlSegment controlSegment
    dataBytes     = unXDelta1DataSegment    dataSegment

    parseControlBody :: ByteParser (MD5Hash, FileSize, [ParsedSourceRecord], [ParsedInstruction])
    parseControlBody = do
      observedTypeTag <- word32BE
      unless (observedTypeTag == xdelta1ControlTypeTag) $
        fail
          ( "control segment opens with type tag 0x"
            ++ showHex observedTypeTag ""
            ++ "; expected ST_XdeltaControl (0x"
            ++ showHex xdelta1ControlTypeTag ""
            ++ "). Canonical xdelta-1.x's EDSIO reader rejects unrecognized"
            ++ " library numbers (low byte of the type tag) with "
            ++ "\"Unregistered library: N\"."
          )
      _allocationBound <- word32BE
        -- Canonical xdelta uses this 32-bit BE word as a hard upper
        -- bound on parser scratch allocations (libedsio/default.c).
        -- Slap doesn't track sub-record allocations, so the value is
        -- read and discarded here; the encoder writes a generous
        -- fixed bound ('xdelta1ControlAllocationBound').
      toMD5 <- MD5Hash <$> getBytes (Length 16)
      targetLength <- edsioVarint
      skip (Length 1)  -- has_data boolean: encoder-derived from
                       -- the data segment's emptiness, parser-
                       -- ignored because the segment carries its
                       -- own length via the patch envelope
      sourceCount <- fromIntegral <$> edsioVarint
      sources <- parseSourceList sourceCount
      instructionCount <- fromIntegral <$> edsioVarint
      instructions <- parseInstructions instructionCount
      pure ( toMD5
           , FileSize (fromIntegral targetLength)
           , sources
           , instructions
           )

-- | Parse a single EDSIO-serialized source record. Returns the raw
-- fields tagged with the wire kind byte; shape validation happens
-- afterwards in 'requireDataAndFileRecords'.
parseOneSource :: ByteParser ParsedSourceRecord
parseOneSource = do
  nameLength <- fromIntegral <$> edsioVarint
  sourceName <- getBytes (Length nameLength)
  md5Bytes <- MD5Hash <$> getBytes (Length 16)
  sourceLength <- edsioVarint
  sourceKindByte <- getByte
  offsetModeByte <- getByte
  let kind       = if sourceKindByte /= 0 then ParsedDataKind else ParsedFileKind
      offsetMode = if offsetModeByte /= 0 then SequentialOffsets else AbsoluteOffsets
  pure ParsedSourceRecord
    { parsedSourceName       = sourceName
    , parsedSourceMD5        = md5Bytes
    , parsedSourceLength     = FileSize (fromIntegral sourceLength)
    , parsedSourceKind       = kind
    , parsedSourceOffsetMode = offsetMode
    }

-- | Parse @count@ source records as a flat list. Shape validation
-- happens afterwards in 'requireDataAndFileRecords'; this function
-- is intentionally permissive over the wire so that off-spec shapes
-- can be reported with structured 'UnsupportedXDelta1Shape' rather
-- than as bare ByteParser-monad failures.
parseSourceList :: Int -> ByteParser [ParsedSourceRecord]
parseSourceList 0 = pure []
parseSourceList count = do
  source <- parseOneSource
  rest <- parseSourceList (count - 1)
  pure (source : rest)

-- | Reduce a parsed source list to the canonical
-- @[data segment, file source]@ pair, or refuse with
-- 'UnsupportedXDelta1Shape'. Canonical xdelta emits exactly that
-- shape ('xdelta.c:241-251' adds the data source, 'xdmain.c:1539-1542'
-- adds the from-file source — both unconditional); any other count
-- or ordering is off-spec and rejected at parse time. The 'String'
-- carried by 'UnsupportedXDelta1Shape' names the offending input
-- ("3 sources", "[file, data]", "[file, file]", "1 source: data",
-- "0 sources", etc.) so the diagnostic reads cleanly without
-- needing a separate render arm per malformation.
requireDataAndFileRecords :: [ParsedSourceRecord] -> Either SlapError ParsedSourcePair
requireDataAndFileRecords sources = case sources of
  [first, second] -> case (parsedSourceKind first, parsedSourceKind second) of
    (ParsedDataKind, ParsedFileKind) -> Right ParsedSourcePair
      { parsedDataRecord = first
      , parsedFileRecord = second
      }
    (ParsedDataKind, ParsedDataKind) -> Left (UnsupportedXDelta1Shape XDelta1TwoDataSources)
    (ParsedFileKind, ParsedDataKind) -> Left (UnsupportedXDelta1Shape XDelta1ReversedDataFileOrder)
    (ParsedFileKind, ParsedFileKind) -> Left (UnsupportedXDelta1Shape XDelta1TwoFileSources)
  []        -> Left (UnsupportedXDelta1Shape XDelta1ZeroSources)
  [single]  -> case parsedSourceKind single of
    ParsedDataKind -> Left (UnsupportedXDelta1Shape XDelta1OneDataSource)
    ParsedFileKind -> Left (UnsupportedXDelta1Shape XDelta1OneFileSource)
  many      -> Left (UnsupportedXDelta1Shape (XDelta1TooManySources (length many)))

-- | Translate the wire-level source index of an instruction to the
-- 'XDelta1InstructionTarget' sum, or refuse with
-- 'XDelta1UnknownInstructionTarget' for indices outside @{0, 1}@.
-- Canonical xdelta emits only those two indices; anything else is
-- off-spec and rejected at parse time so 'applyXDelta1' can dispatch
-- on a total two-arm pattern without runtime bounds checking.
translateInstruction :: ParsedInstruction -> Either SlapError XDelta1Instruction
translateInstruction parsed = case parsedInstructionWireIndex parsed of
  0 -> Right XDelta1Instruction
        { xdelta1InstructionTarget = FromDataSource
        , xdelta1InstructionOffset = parsedInstructionOffset parsed
        , xdelta1InstructionLength = parsedInstructionLength parsed
        }
  1 -> Right XDelta1Instruction
        { xdelta1InstructionTarget = FromFileSource
        , xdelta1InstructionOffset = parsedInstructionOffset parsed
        , xdelta1InstructionLength = parsedInstructionLength parsed
        }
  other -> Left (XDelta1UnknownInstructionTarget other)

parseInstructions :: Int -> ByteParser [ParsedInstruction]
parseInstructions 0 = pure []
parseInstructions count = do
  wireIndex <- edsioVarint
  offset <- Offset . fromIntegral <$> edsioVarint
  instructionLength <- FileSize . fromIntegral <$> edsioVarint
  rest <- parseInstructions (count - 1)
  pure (ParsedInstruction wireIndex offset instructionLength : rest)

-- | When a source uses sequential-offset mode, on-wire instruction
-- offsets are zero and the real offset is the running total of all
-- preceding instructions' lengths against that source. The data
-- record's offset-mode is consulted for data-targeting instructions;
-- the file source's for file-targeting instructions. Folds across
-- instructions maintaining a per-target running position.
fixSequentialOffsets :: XDelta1OffsetMode -> XDelta1OffsetMode -> [XDelta1Instruction] -> [XDelta1Instruction]
fixSequentialOffsets dataOffsetMode fileOffsetMode instructions =
  reverse (snd (foldl' resolveSequentialOffset (initialPositions, []) instructions))
  where
    dataIsSequential = dataOffsetMode == SequentialOffsets
    fileIsSequential = fileOffsetMode == SequentialOffsets

    initialPositions :: SequentialPositions
    initialPositions = SequentialPositions
      { dataPosition = 0
      , filePosition = 0
      }

    resolveSequentialOffset (positions, accumulated) instruction =
      case xdelta1InstructionTarget instruction of
        FromDataSource
          | dataIsSequential ->
              let rawOffset = dataPosition positions
                  advanced  = rawOffset + unFileSize (xdelta1InstructionLength instruction)
                  updated   = positions { dataPosition = advanced }
              in ( updated
                 , instruction { xdelta1InstructionOffset = Offset rawOffset } : accumulated
                 )
          | otherwise -> (positions, instruction : accumulated)
        FromFileSource
          | fileIsSequential ->
              let rawOffset = filePosition positions
                  advanced  = rawOffset + unFileSize (xdelta1InstructionLength instruction)
                  updated   = positions { filePosition = advanced }
              in ( updated
                 , instruction { xdelta1InstructionOffset = Offset rawOffset } : accumulated
                 )
          | otherwise -> (positions, instruction : accumulated)

-- | Per-target running positions for 'fixSequentialOffsets'.
-- Replaces the prior association-list lookup with two named fields;
-- there are only ever two sources so the structure is fixed-shape.
-- Internal to the parser; not exported.
data SequentialPositions = SequentialPositions
  { dataPosition :: !Int
  , filePosition :: !Int
  }
