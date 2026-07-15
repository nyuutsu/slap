{-# LANGUAGE OverloadedStrings #-}

module Slap.XDelta1.Parse
  ( parseXDelta1
  , parseVersion1Point1
  , parseControl
  , parseOneSource
  , parseInstructions
  , ParsedSourceShape(..)
  , classifyParsedSourceList
  , translateInstruction
  , fixSequentialOffsets
    -- * Role newtypes for parseControl arguments
  , XDelta1ControlSegment(..)
  , XDelta1DataSegment(..)
  , XDelta1NoVerifyFlag(..)
  ) where

-- Canonical reference: xdelta 1.x source, preserved at docs/xdelta1/upstream/xdelta-1.1.3.tar.gz

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Instruction(..)
    , XDelta1SourceRoster(..), XDelta1FileSource(..)
    , XDelta1InstructionTarget(..)
    , XDelta1OffsetMode(..)
    , XDelta1VerificationPosture(..)
    , XDelta1PatchCompression(..)
    , XDelta1FileAtDeltaTime(..)
    , XDelta1FromName(..)
    , XDelta1ToName(..)
    , xdelta1MagicLength
    , xdelta1HeaderBlockLength
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
import Data.Word (Word8)
import Slap.Status (SlapError(..), DecompressionFailure(..), Parsed(..),
                    SlapAdvisory(..),
                    ByteParserError(ByteParserXDelta1UnexpectedControlTypeTag),
                    XDelta1KnownUnsupportedVersion(..),
                    XDelta1ShapeViolation(..), XDelta1SourceListShape(..),
                    XDelta1SourceFlag(..), XDelta1DataRecordNameAsRead(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, throwByteParserError, getByte, getBytes, skip, edsioVarint, word32BE)
import Slap.Measure (Length(..), FileSize(..), Offset(Offset), offsetFromParsed,
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ExpectedMagic(..),
                     ExpectedSize(..), ActualSize(..), byteLength)
import Slap.Compression.Stream (gzipInflate)
import Slap.Text (EncodingName(..), decodeTextLenient, decodeLossAdvisories)

import Control.Monad (unless)
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), shiftR)
import Data.Int (Int64)
import Data.List (mapAccumL)

----------------------------------------------------------------------------
-- Role newtypes for 'parseControl'
----------------------------------------------------------------------------

-- | The decompressed control segment — the EDSIO-serialized record stream.
newtype XDelta1ControlSegment = XDelta1ControlSegment
  { unXDelta1ControlSegment :: ByteString
  } deriving (Eq, Show)

-- | The decompressed data segment — the literal payload instructions copy from.
newtype XDelta1DataSegment = XDelta1DataSegment
  { unXDelta1DataSegment :: ByteString
  } deriving (Eq, Show)

-- | Whether the header's @FLAG_NO_VERIFY@ bit (bit 0) was set.
data XDelta1NoVerifyFlag
  = NoVerifyFlagClear
  | NoVerifyFlagSet
  deriving (Show, Eq)

data ParsedSourceKind
  = ParsedDataKind
  | ParsedFileKind
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseXDelta1 :: EncodingName -> PatchFileContents -> Either SlapError (Parsed XDelta1Patch)
parseXDelta1 metadataEncoding patchContents@(PatchFileContents input)
    -- coarse floor; the real minimum is checked in parseVersion1Point1
  | ByteString.length input < xdelta1MagicLength + xdelta1TrailerSize =
      Left (InputTooShort LabelXDelta1
              (RequiredLength (Length (fromIntegral (xdelta1MagicLength + xdelta1TrailerSize))))
              (ActualLength (byteLength input)))
  | magic == "%XDZ004%" = parseVersion1Point1 metadataEncoding patchContents (ExpectedMagic magic)
  | magic == "%XDZ003%" = Left (UnsupportedXDelta1Subformat XDelta1_1_0_4)
  | magic == "%XDZ002%" = Left (UnsupportedXDelta1Subformat XDelta1_1_0)
  | ByteString.take 7 input == "%XDELTA" = Left (UnsupportedXDelta1Subformat XDelta1_0_14)
  | otherwise = Left (BadMagic LabelXDelta1 (ActualMagic (ByteString.take xdelta1MagicLength input)))
  where
    magic = ByteString.take xdelta1MagicLength input

-- | Body parser for @%XDZ004%@ (xdelta 1.1.x), the only xdelta1 era
-- slap currently supports. Sibling body parsers for other eras
-- (1.0.4 under @%XDZ003%@, 1.0.x under @%XDZ002%@) would live
-- alongside this one and be dispatched to by 'parseXDelta1'.
parseVersion1Point1 :: EncodingName -> PatchFileContents -> ExpectedMagic -> Either SlapError (Parsed XDelta1Patch)
parseVersion1Point1 metadataEncoding (PatchFileContents input) expectedMagic
  | totalLength < xdelta1MagicLength + xdelta1HeaderBlockLength + xdelta1TrailerSize =
      Left (InputTooShort LabelXDelta1
              (RequiredLength (Length (fromIntegral (xdelta1MagicLength + xdelta1HeaderBlockLength + xdelta1TrailerSize))))
              (ActualLength (Length (fromIntegral totalLength))))
  | trailingMagic /= unExpectedMagic expectedMagic = Left (TrailingMagicMismatch LabelXDelta1 expectedMagic (ActualMagic trailingMagic))
  | otherwise = do
      decompressedData    <- safeDecompressGZip dataSegmentRaw
      decompressedControl <- safeDecompressGZip controlSegmentRaw
      let (fromText, fromNotices) = decodeTextLenient metadataEncoding fromNameBytes
          (toText,   toNotices)   = decodeTextLenient metadataEncoding toNameBytes
          headerNameAdvisories =
            decodeLossAdvisories LabelXDelta1 FieldXDelta1FromName fromNotices
            ++ decodeLossAdvisories LabelXDelta1 FieldXDelta1ToName toNotices
      Parsed patch warnings <-
        parseControl metadataEncoding
                     noVerifyFlag
                     compressionPosture
                     (XDelta1ControlSegment decompressedControl)
                     (XDelta1DataSegment    decompressedData)
                     (XDelta1FromName       fromText)
                     (XDelta1ToName         toText)
      Right (Parsed (recordInputPreCompression patch)
                    (headerNameAdvisories ++ warnings))
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

    fixedPrefixLength = xdelta1MagicLength + xdelta1HeaderBlockLength

    -- Header: 6 x uint32 BE immediately after the magic
    flags    = getWord32BE xdelta1MagicLength input
    nameLengths = getWord32BE (xdelta1MagicLength + 4) input
    fromNameLength = fromIntegral (nameLengths `shiftR` 16) :: Int
    toNameLength   = fromIntegral (nameLengths .&. 0xFFFF) :: Int
    fromNameBytes = ByteString.take fromNameLength (ByteString.drop fixedPrefixLength input)
    toNameBytes   = ByteString.take toNameLength (ByteString.drop (fixedPrefixLength + fromNameLength) input)
    headerOffset = fixedPrefixLength + fromNameLength + toNameLength

    -- Trailer: last 12 bytes = control_offset (4B) + magic (8B)
    trailerOffset = totalLength - xdelta1TrailerSize
    controlOffset = fromIntegral (getWord32BE trailerOffset input) :: Int
    trailingMagic = ByteString.take xdelta1MagicLength (ByteString.drop (totalLength - xdelta1MagicLength) input)

    -- Decompress segments if FLAG_PATCH_COMPRESSED (bit 3)
    compressed   = flags .&. xdelta1FlagPatchCompressed /= 0
    compressionPosture = if compressed then CompressedPatch else UncompressedPatch
    noVerifyFlag = if flags .&. xdelta1FlagNoVerify /= 0
                     then NoVerifyFlagSet
                     else NoVerifyFlagClear
    dataSegmentRaw = ByteString.take (controlOffset - headerOffset) (ByteString.drop headerOffset input)
    controlSegmentRaw = ByteString.take (trailerOffset - controlOffset) (ByteString.drop controlOffset input)

    safeDecompressGZip raw
      | not compressed      = Right raw
      | ByteString.null raw = Right ByteString.empty
      | otherwise           = first (DecompressionFailed . XDelta1Failed) (gzipInflate raw)

-- | An xdelta1 source record straight off the wire, with its two boolean flags still raw bytes.
-- 'validateSourceFlags' decodes them into a 'ParsedSourceRecord', refusing a flag the format leaves undefined.
-- Internal to the parser; not exported.
data RawSourceRecord = RawSourceRecord
  { rawSourceName           :: !ByteString
  , rawSourceMD5            :: !MD5Hash
  , rawSourceLength         :: !FileSize
  , rawSourceKindByte       :: !Word8
  , rawSourceOffsetModeByte :: !Word8
  } deriving (Show, Eq)

-- | An xdelta1 source record with its two flag bytes decoded to enums by 'validateSourceFlags', before the @[data, file]@ shape has been validated.
-- The MD5 is still the raw wire value; the verification posture is folded in per-side later, in 'parseControl'.
-- 'requireDataAndFileRecords' reads 'parsedSourceKind' to verify the canonical ordering and refuse anything else.
-- Internal to the parser; not exported.
data ParsedSourceRecord = ParsedSourceRecord
  { parsedSourceName       :: !ByteString
  , parsedSourceMD5        :: !MD5Hash
  , parsedSourceLength     :: !FileSize
  , parsedSourceKind       :: !ParsedSourceKind
  , parsedSourceOffsetMode :: !XDelta1OffsetMode
  } deriving (Show, Eq)

-- | 'parseControl' folds this into the patch's 'XDelta1SourceRoster' once the verification posture is known;
-- until then the raw records stay whole, so the data-record checks and the no-verify curio check can still read the MD5 slots.
data ParsedSourceShape
  = ParsedDataAndFile !ParsedSourceRecord !ParsedSourceRecord
  | ParsedDataOnly    !ParsedSourceRecord
  | ParsedFileOnly    !ParsedSourceRecord
  | ParsedNoSources
  deriving (Show, Eq)

shapeDataRecord :: ParsedSourceShape -> Maybe ParsedSourceRecord
shapeDataRecord (ParsedDataAndFile dataRecord _) = Just dataRecord
shapeDataRecord (ParsedDataOnly dataRecord)      = Just dataRecord
shapeDataRecord (ParsedFileOnly _)               = Nothing
shapeDataRecord ParsedNoSources                  = Nothing

shapeFileRecord :: ParsedSourceShape -> Maybe ParsedSourceRecord
shapeFileRecord (ParsedDataAndFile _ fileRecord) = Just fileRecord
shapeFileRecord (ParsedDataOnly _)               = Nothing
shapeFileRecord (ParsedFileOnly fileRecord)      = Just fileRecord
shapeFileRecord ParsedNoSources                  = Nothing

sourceListShapeOf :: ParsedSourceShape -> XDelta1SourceListShape
sourceListShapeOf ParsedDataAndFile{} = SourceListDataAndFile
sourceListShapeOf ParsedDataOnly{}    = SourceListDataOnly
sourceListShapeOf ParsedFileOnly{}    = SourceListFileOnly
sourceListShapeOf ParsedNoSources     = SourceListEmpty

-- | The decoded control body, before source-flag and shape validation.
data ParsedControlBody = ParsedControlBody
  { parsedControlTargetMD5    :: !MD5Hash
  , parsedControlTargetLength :: !FileSize
  , parsedControlSources      :: ![RawSourceRecord]
  , parsedControlInstructions :: ![ParsedInstruction]
  }

-- | An xdelta1 instruction with its source index still raw — the 'Int64' from the EDSIO varint,
-- resolved to an 'XDelta1InstructionTarget' only later, by 'translateInstruction'.
data ParsedInstruction = ParsedInstruction
  { parsedInstructionWireIndex :: !Int64
  , parsedInstructionOffset    :: !Offset
  , parsedInstructionLength    :: !FileSize
  } deriving (Show, Eq)

-- Smallest a control body can be: the type tag (4) and allocation-bound (4) prelude, the target MD5 (16),
-- then the four leanest trailing fields —
-- a 1-byte target-length varint, the has_data byte, and 1-byte source-count and instruction-count varints.
xdelta1ControlSegmentFloor :: Int
xdelta1ControlSegmentFloor = 4 + 4 + 16 + 4

-- | Parse the control segment into an 'XDelta1Patch'.
-- One subtlety: canonical's converter (@xdelta.c:1433-1471@) can emit absolute-mode data records, not only sequential ones.
--
-- Only the control-derived warnings are emitted here; the header-name decode advisories are 'parseVersion1Point1''s.
parseControl :: EncodingName
             -> XDelta1NoVerifyFlag
             -> XDelta1PatchCompression
             -> XDelta1ControlSegment
             -> XDelta1DataSegment
             -> XDelta1FromName
             -> XDelta1ToName
             -> Either SlapError (Parsed XDelta1Patch)
parseControl metadataEncoding noVerifyFlag compressionPosture controlSegment dataSegment fromName toName
  | ByteString.length controlBytes < xdelta1ControlSegmentFloor =
      Left (XDelta1ControlSegmentTooShort
              (RequiredLength (Length (fromIntegral xdelta1ControlSegmentFloor)))
              (ActualLength (byteLength controlBytes)))
  | otherwise = do
      parsedBody <- runFormatParser LabelXDelta1 parseControlBody controlBytes
      let toMD5        = parsedControlTargetMD5 parsedBody
          targetLength = parsedControlTargetLength parsedBody
          rawSources   = parsedControlSources parsedBody
          parsedInstrs = parsedControlInstructions parsedBody
      parsedSources <- traverse validateSourceFlags rawSources
      sourceShape <- classifyParsedSourceList parsedSources
      let maybeDataRecord   = shapeDataRecord sourceShape
          maybeFileRecord   = shapeFileRecord sourceShape
          dataSegmentLength = ByteString.length dataBytes
      -- The data area and the source list must agree: a data record's length is the segment's byte count, and no data record means no segment bytes.
      case maybeDataRecord of
        Just dataRecord ->
          unless (unFileSize (parsedSourceLength dataRecord) == fromIntegral dataSegmentLength) $
            Left $ XDelta1DataRecordLengthMismatch
              (ExpectedSize (parsedSourceLength dataRecord))
              (ActualSize (FileSize (fromIntegral dataSegmentLength)))
        Nothing ->
          unless (dataSegmentLength == 0) $
            Left (XDelta1DanglingDataSegment (ActualSize (FileSize (fromIntegral dataSegmentLength))))
      let verificationPosture = case noVerifyFlag of
            NoVerifyFlagSet   -> CreatorOptedOutOfVerification
            NoVerifyFlagClear -> VerifyAgainstStoredMD5s toMD5
      case (verificationPosture, maybeDataRecord) of
        (VerifyAgainstStoredMD5s _, Just dataRecord) ->
          let computedDataMD5 = md5 dataBytes
              declaredDataMD5 = parsedSourceMD5 dataRecord
          in unless (computedDataMD5 == declaredDataMD5) $
               Left $ XDelta1DataRecordMD5Mismatch declaredDataMD5 computedDataMD5
        _ -> Right ()
      translatedInstructions <-
        traverse (translateInstruction (sourceListShapeOf sourceShape)) parsedInstrs
      let fileSourceFromRecord fileRecord =
            let (fileNameText, fileNameNotices) =
                  decodeTextLenient metadataEncoding (parsedSourceName fileRecord)
            in ( XDelta1FileSource
                   { xdelta1FileSourceName       = XDelta1FromName fileNameText
                   , xdelta1FileSourceMD5        = case verificationPosture of
                       VerifyAgainstStoredMD5s _     -> Just (parsedSourceMD5 fileRecord)
                       CreatorOptedOutOfVerification -> Nothing
                   , xdelta1FileSourceLength     = parsedSourceLength fileRecord
                   , xdelta1FileSourceOffsetMode = parsedSourceOffsetMode fileRecord
                   }
               , decodeLossAdvisories LabelXDelta1 FieldXDelta1FromName fileNameNotices )
          (roster, sourceNameAdvisories) = case sourceShape of
            ParsedDataAndFile _ fileRecord ->
              let (fileSource, nameAdvisories) = fileSourceFromRecord fileRecord
              in (DataAndFileSources fileSource, nameAdvisories)
            ParsedDataOnly _ -> (DataSourceOnly, [])
            ParsedFileOnly fileRecord ->
              let (fileSource, nameAdvisories) = fileSourceFromRecord fileRecord
              in (FileSourceOnly fileSource, nameAdvisories)
            ParsedNoSources -> (NoSources, [])
          -- These fallbacks are never reached: 'translateInstruction' admits no instruction targeting a source the shape lacks.
          dataOffsetMode = maybe SequentialOffsets parsedSourceOffsetMode maybeDataRecord
          fileOffsetMode = maybe AbsoluteOffsets   parsedSourceOffsetMode maybeFileRecord
          fixedInstructions =
            fixSequentialOffsets dataOffsetMode fileOffsetMode translatedInstructions
          patch = XDelta1Patch
            { xdelta1FromName         = fromName
            , xdelta1ToName           = toName
            , xdelta1Verification     = verificationPosture
            , xdelta1PatchCompression = compressionPosture
              -- 'parseVersion1Point1' overrides both fields after the parse returns.
            , xdelta1FromAtDeltaTime  = FileWasRawBytes
            , xdelta1ToAtDeltaTime    = FileWasRawBytes
            , xdelta1TargetLength     = targetLength
            , xdelta1SourceRoster     = roster
            , xdelta1Instructions     = fixedInstructions
            , xdelta1DataSegment      = dataBytes
            }
          dataNameNotices = case maybeDataRecord of
            Just dataRecord
              | parsedSourceName dataRecord /= xdelta1DataRecordName ->
                  [XDelta1DataRecordNameDiverges (XDelta1DataRecordNameAsRead (parsedSourceName dataRecord))]
            _ -> []
          postureWarnings = case verificationPosture of
            VerifyAgainstStoredMD5s _      -> []
            CreatorOptedOutOfVerification  -> [VerificationOptedOutByCreator LabelXDelta1]
          storedMD5Slots = toMD5 : map parsedSourceMD5 parsedSources
          curioWarnings = case noVerifyFlag of
            NoVerifyFlagClear -> []
            NoVerifyFlagSet
              | all (== xdelta1EmptyInputMD5Sentinel) storedMD5Slots -> []
              | otherwise -> [XDelta1NoVerifyWithDivergentSentinel]
      Right (Parsed patch (sourceNameAdvisories ++ dataNameNotices
                             ++ postureWarnings ++ curioWarnings))
  where
    controlBytes  = unXDelta1ControlSegment controlSegment
    dataBytes     = unXDelta1DataSegment    dataSegment

    parseControlBody :: ByteParser ParsedControlBody
    parseControlBody = do
      observedTypeTag <- word32BE
      unless (observedTypeTag == xdelta1ControlTypeTag) $
        throwByteParserError (ByteParserXDelta1UnexpectedControlTypeTag observedTypeTag)
      _allocationBound <- word32BE
        -- Canonical xdelta uses this 32-bit BE word as a hard upper
        -- bound on parser scratch allocations (libedsio/default.c).
        -- Slap doesn't track sub-record allocations, so the value is
        -- read and discarded here; the encoder writes a generous
        -- fixed bound ('xdelta1ControlAllocationBound').
      toMD5 <- MD5Hash <$> getBytes (Length 16)
      targetLength <- edsioVarint
      -- has_data: a redundant flag, derived from the per-source isdata flags slap reads, so the byte itself is never consulted.
      skip (Length 1)
      sourceCount <- fromIntegral <$> edsioVarint
      sources <- parseSourceList sourceCount
      instructionCount <- fromIntegral <$> edsioVarint
      instructions <- parseInstructions instructionCount
      pure ParsedControlBody
        { parsedControlTargetMD5    = toMD5
        , parsedControlTargetLength = FileSize (fromIntegral targetLength)
        , parsedControlSources      = sources
        , parsedControlInstructions = instructions
        }

-- | Parse a single EDSIO-serialized source record off the wire, its flag bytes still raw —
-- 'validateSourceFlags' decodes them afterwards.
parseOneSource :: ByteParser RawSourceRecord
parseOneSource = do
  nameLength <- fromIntegral <$> edsioVarint
  sourceName <- getBytes (Length nameLength)
  md5Bytes <- MD5Hash <$> getBytes (Length 16)
  sourceLength <- edsioVarint
  sourceKindByte <- getByte
  offsetModeByte <- getByte
  pure RawSourceRecord
    { rawSourceName           = sourceName
    , rawSourceMD5            = md5Bytes
    , rawSourceLength         = FileSize (fromIntegral sourceLength)
    , rawSourceKindByte       = sourceKindByte
    , rawSourceOffsetModeByte = offsetModeByte
    }

-- | Parse @count@ source records off the wire as a flat list, flag bytes still raw.
parseSourceList :: Int -> ByteParser [RawSourceRecord]
parseSourceList 0 = pure []
parseSourceList count = do
  source <- parseOneSource
  rest <- parseSourceList (count - 1)
  pure (source : rest)

-- | Decode a raw source record's two boolean flag bytes into their enums, refusing if either holds a value the format leaves undefined.
-- isdata and sequential are booleans; the only defined bytes are 0 and 1.
-- This diverges from canonical xdelta, which reads any nonzero byte as set.
validateSourceFlags :: RawSourceRecord -> Either SlapError ParsedSourceRecord
validateSourceFlags raw = do
  kind       <- decodeSourceKind (rawSourceKindByte raw)
  offsetMode <- decodeOffsetMode (rawSourceOffsetModeByte raw)
  pure ParsedSourceRecord
    { parsedSourceName       = rawSourceName raw
    , parsedSourceMD5        = rawSourceMD5 raw
    , parsedSourceLength     = rawSourceLength raw
    , parsedSourceKind       = kind
    , parsedSourceOffsetMode = offsetMode
    }
  where
    -- Canonical: the data source is kind byte 1 (@xdelta.c:246@), the from-file source 0 (@xdmain.c:1539-1542@).
    decodeSourceKind 0         = Right ParsedFileKind
    decodeSourceKind 1         = Right ParsedDataKind
    decodeSourceKind byteValue = Left (XDelta1NonBooleanSourceFlag XDelta1SourceKindFlag byteValue)
    decodeOffsetMode 0         = Right AbsoluteOffsets
    decodeOffsetMode 1         = Right SequentialOffsets
    decodeOffsetMode byteValue = Left (XDelta1NonBooleanSourceFlag XDelta1SourceOffsetModeFlag byteValue)

classifyParsedSourceList :: [ParsedSourceRecord] -> Either SlapError ParsedSourceShape
classifyParsedSourceList sources = case sources of
  [] -> Right ParsedNoSources
  [onlySource] -> case parsedSourceKind onlySource of
    ParsedDataKind -> Right (ParsedDataOnly onlySource)
    ParsedFileKind -> Right (ParsedFileOnly onlySource)
  [firstSource, secondSource] -> case (parsedSourceKind firstSource, parsedSourceKind secondSource) of
    (ParsedDataKind, ParsedFileKind) -> Right (ParsedDataAndFile firstSource secondSource)
    (ParsedDataKind, ParsedDataKind) -> Left (UnsupportedXDelta1Shape XDelta1TwoDataSources)
    (ParsedFileKind, ParsedDataKind) -> Left (UnsupportedXDelta1Shape XDelta1ReversedDataFileOrder)
    (ParsedFileKind, ParsedFileKind) -> Left (UnsupportedXDelta1Shape XDelta1TwoFileSources)
  surplusSources -> Left (UnsupportedXDelta1Shape (XDelta1TooManySources (length surplusSources)))

-- | Resolve an instruction's raw wire index against the emitted list's shape (@control_reindex@ semantics):
-- an index counts positions in the list, so a lone file source is index 0, not 1.
-- An index the shape has no position for refuses with 'XDelta1UnknownInstructionTarget'.
translateInstruction :: XDelta1SourceListShape -> ParsedInstruction -> Either SlapError XDelta1Instruction
translateInstruction listShape parsed =
  case (listShape, parsedInstructionWireIndex parsed) of
    (SourceListDataAndFile, 0)            -> Right (instructionTargeting FromDataSource)
    (SourceListDataAndFile, 1)            -> Right (instructionTargeting FromFileSource)
    (SourceListDataAndFile, unknownIndex) -> refuse unknownIndex
    (SourceListDataOnly,    0)            -> Right (instructionTargeting FromDataSource)
    (SourceListDataOnly,    unknownIndex) -> refuse unknownIndex
    (SourceListFileOnly,    0)            -> Right (instructionTargeting FromFileSource)
    (SourceListFileOnly,    unknownIndex) -> refuse unknownIndex
    (SourceListEmpty,       unknownIndex) -> refuse unknownIndex
  where
    refuse unknownIndex = Left (XDelta1UnknownInstructionTarget listShape unknownIndex)
    instructionTargeting target = XDelta1Instruction
      { xdelta1InstructionTarget = target
      , xdelta1InstructionOffset = parsedInstructionOffset parsed
      , xdelta1InstructionLength = parsedInstructionLength parsed
      }

parseInstructions :: Int -> ByteParser [ParsedInstruction]
parseInstructions 0 = pure []
parseInstructions count = do
  wireIndex <- edsioVarint
  offset <- offsetFromParsed <$> edsioVarint
  instructionLength <- FileSize . fromIntegral <$> edsioVarint
  rest <- parseInstructions (count - 1)
  pure (ParsedInstruction wireIndex offset instructionLength : rest)

-- | Reconstruct each sequential-mode instruction's real offset (see 'XDelta1OffsetMode').
-- The data record's mode governs data-targeting instructions; the file source's, file-targeting ones.
fixSequentialOffsets :: XDelta1OffsetMode -> XDelta1OffsetMode -> [XDelta1Instruction] -> [XDelta1Instruction]
fixSequentialOffsets dataOffsetMode fileOffsetMode instructions =
  snd (mapAccumL resolveSequentialOffset initialPositions instructions)
  where
    dataIsSequential = dataOffsetMode == SequentialOffsets
    fileIsSequential = fileOffsetMode == SequentialOffsets

    initialPositions :: SequentialPositions
    initialPositions = SequentialPositions
      { dataPosition = 0
      , filePosition = 0
      }

    resolveSequentialOffset :: SequentialPositions -> XDelta1Instruction
                            -> (SequentialPositions, XDelta1Instruction)
    resolveSequentialOffset positions instruction =
      case xdelta1InstructionTarget instruction of
        FromDataSource
          | dataIsSequential ->
              let rawOffset = dataPosition positions
                  advanced  = rawOffset + unFileSize (xdelta1InstructionLength instruction)
              in ( positions { dataPosition = advanced }
                 , instruction { xdelta1InstructionOffset = Offset rawOffset }
                 )
          | otherwise -> (positions, instruction)
        FromFileSource
          | fileIsSequential ->
              let rawOffset = filePosition positions
                  advanced  = rawOffset + unFileSize (xdelta1InstructionLength instruction)
              in ( positions { filePosition = advanced }
                 , instruction { xdelta1InstructionOffset = Offset rawOffset }
                 )
          | otherwise -> (positions, instruction)

-- | Per-target running positions for 'fixSequentialOffsets'.
-- There are only ever two sources, so the structure is fixed-shape.
data SequentialPositions = SequentialPositions
  { dataPosition :: !Int64
  , filePosition :: !Int64
  }
