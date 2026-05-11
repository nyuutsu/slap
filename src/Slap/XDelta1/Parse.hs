{-# LANGUAGE OverloadedStrings #-}

module Slap.XDelta1.Parse
  ( parseXDelta1
  , parseVersion1Point1
  , parseControl
  , parseOneSource
  , parseInstructions
  , requireDataAndFileRecords
  , applyPostureToSources
  , translateInstruction
  , fixSequentialOffsets
    -- * Role newtypes for parseControl arguments
  , XDelta1ControlSegment(..)
  , XDelta1DataSegment(..)
  , XDelta1FromName(..)
  , XDelta1ToName(..)
  , XDelta1NoVerifyFlag(..)
  ) where

-- Canonical reference: tools/xdelta1/xdelta-1.1.4/ (xdelta 1.x source)

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..)
    , XDelta1Sources(..)
    , XDelta1InstructionTarget(..)
    , XDelta1OffsetMode(..)
    , XDelta1VerificationPosture(..)
    , xdelta1TrailerSize
    , xdelta1EmptyInputMD5Sentinel
    )
import Slap.Binary (getWord32BE)
import Slap.Checksum (MD5Hash(..))
import Slap.Error (SlapError(..), DecompressionFailure(..), Parsed(..), SlapWarning(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, skip, edsioVarint)
import Slap.Measure (Length(..), FileSize(..), Offset(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ExpectedMagic(..))
import Slap.Compression.Stream (gzipInflate)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), shiftR, testBit)
import Data.Int (Int64)

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

-- | The from-name field parsed out of an XDelta1 patch header:
-- the name the patch records as the source filename.
newtype XDelta1FromName = XDelta1FromName
  { unXDelta1FromName :: ByteString
  } deriving (Eq, Show)

-- | The to-name field parsed out of an XDelta1 patch header: the
-- name the patch records as the target filename. Distinct from
-- 'XDelta1FromName' so a transposition at 'parseControl' would
-- silently produce a patch with reversed source/target names; the
-- newtype boundary forces the spec direction at the call site.
newtype XDelta1ToName = XDelta1ToName
  { unXDelta1ToName :: ByteString
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

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseXDelta1 :: PatchFileContents -> Either SlapError (Parsed XDelta1Patch)
parseXDelta1 patchContents@(PatchFileContents input)
  | ByteString.length input < 20 = Left (InputTooShort LabelXDelta1 (RequiredLength (Length 20)) (ActualLength (Length (ByteString.length input))))
  | magic == "%XDZ004%" = parseVersion1Point1 patchContents (ExpectedMagic magic)
  | magic == "%XDZ003%" = Left (UnsupportedSubformat LabelXDelta1 "version 1.0.4")
  | magic == "%XDZ002%" = Left (UnsupportedSubformat LabelXDelta1 "version 1.0")
  | ByteString.take 7 input == "%XDELTA" = Left (UnsupportedSubformat LabelXDelta1 "version 0.14")
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
      parseControl noVerifyFlag
                   (XDelta1ControlSegment decompressedControl)
                   (XDelta1DataSegment    decompressedData)
                   (XDelta1FromName       fromName)
                   (XDelta1ToName         toName)
  where
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
    compressed   = testBit flags 3
    noVerifyFlag = if testBit flags 0 then NoVerifyFlagSet else NoVerifyFlagClear
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
-- validated. 'parsedSourceWireKind' captures the wire's source-kind
-- byte so 'requireDataAndFileRecords' can verify the canonical
-- ordering and refuse anything else. Internal to the parser; not
-- exported.
data ParsedSourceRecord = ParsedSourceRecord
  { parsedSourceName       :: !ByteString
  , parsedSourceMD5        :: !MD5Hash
  , parsedSourceLength     :: !FileSize
  , parsedSourceWireKind   :: !ParsedSourceWireKind
  , parsedSourceOffsetMode :: !XDelta1OffsetMode
  } deriving (Show, Eq)

-- | The two source-kind values the wire format can carry, named
-- inside the parser. 'requireDataAndFileRecords' consults this to
-- verify the canonical ordering (data at index 0, file at index 1)
-- and refuses otherwise. Internal to the parser; not exported.
data ParsedSourceWireKind
  = WireKindData
  | WireKindFile
  deriving (Show, Eq)

-- | The two records that survive shape validation, in canonical
-- @[data, file]@ order. Carries the pre-posture-folding records so
-- 'applyPostureToSources' can produce the public 'XDelta1Sources'
-- and the curio-warning check can consult the raw MD5s. Internal
-- to the parser; not exported.
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
-- All xdelta1 parse warnings are emitted here: the family
-- 'VerificationOptedOutByCreator' under 'NoVerifyFlagSet', and the
-- 'XDelta1NoVerifyWithDivergentSentinel' curio when the flag is set
-- but the stored MD5 slots do not match 'xdelta1EmptyInputMD5Sentinel'.
parseControl :: XDelta1NoVerifyFlag
             -> XDelta1ControlSegment
             -> XDelta1DataSegment
             -> XDelta1FromName
             -> XDelta1ToName
             -> Either SlapError (Parsed XDelta1Patch)
parseControl noVerifyFlag controlSegment dataSegment fromName toName
  | ByteString.length controlBytes < 28 =
      Left (TruncatedRecord LabelXDelta1 0 (Length 28) (Length (ByteString.length controlBytes)))
  | otherwise = do
      (toMD5, targetLength, parsedSources, parsedInstrs) <-
        case runGet parseControlBody controlBytes of
          Left errorMessage -> Left (ParseError LabelXDelta1 errorMessage)
          Right result      -> Right result
      sourcePair <- requireDataAndFileRecords parsedSources
      let verificationPosture = case noVerifyFlag of
            NoVerifyFlagSet   -> CreatorOptedOutOfVerification
            NoVerifyFlagClear -> VerifyAgainstStoredMD5s toMD5
          sources = applyPostureToSources verificationPosture sourcePair
      translatedInstructions <- traverse translateInstruction parsedInstrs
      let fixedInstructions = fixSequentialOffsets sources translatedInstructions
          patch = XDelta1Patch fromNameBytes toNameBytes
                               verificationPosture targetLength sources
                               fixedInstructions dataBytes
          postureWarnings = case verificationPosture of
            VerifyAgainstStoredMD5s _      -> []
            CreatorOptedOutOfVerification  -> [VerificationOptedOutByCreator LabelXDelta1]
          curioWarnings = case noVerifyFlag of
            NoVerifyFlagClear -> []
            NoVerifyFlagSet
              | all (== xdelta1EmptyInputMD5Sentinel)
                    [ toMD5
                    , parsedSourceMD5 (parsedDataRecord sourcePair)
                    , parsedSourceMD5 (parsedFileRecord sourcePair)
                    ]
                  -> []
              | otherwise
                  -> [XDelta1NoVerifyWithDivergentSentinel]
      Right (Parsed patch (postureWarnings ++ curioWarnings))
  where
    controlBytes  = unXDelta1ControlSegment controlSegment
    dataBytes     = unXDelta1DataSegment    dataSegment
    fromNameBytes = unXDelta1FromName       fromName
    toNameBytes   = unXDelta1ToName         toName

    parseControlBody :: Get (MD5Hash, FileSize, [ParsedSourceRecord], [ParsedInstruction])
    parseControlBody = do
      skip (Length 8)  -- type tag + allocation (deprecated)
      toMD5 <- MD5Hash <$> getBytes (Length 16)
      targetLength <- edsioVarint
      skip (Length 1)  -- has_data boolean
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
-- fields tagged with the wire kind byte; shape validation and
-- posture folding happen afterwards in 'requireDataAndFileRecords'
-- and 'applyPostureToSources'.
parseOneSource :: Get ParsedSourceRecord
parseOneSource = do
  nameLength <- fromIntegral <$> edsioVarint
  sourceName <- getBytes (Length nameLength)
  md5Bytes <- MD5Hash <$> getBytes (Length 16)
  sourceLength <- edsioVarint
  sourceKindByte <- getByte
  offsetModeByte <- getByte
  let wireKind   = if sourceKindByte /= 0 then WireKindData else WireKindFile
      offsetMode = if offsetModeByte /= 0 then SequentialOffsets else AbsoluteOffsets
  pure ParsedSourceRecord
    { parsedSourceName       = sourceName
    , parsedSourceMD5        = md5Bytes
    , parsedSourceLength     = FileSize (fromIntegral sourceLength)
    , parsedSourceWireKind   = wireKind
    , parsedSourceOffsetMode = offsetMode
    }

-- | Parse @count@ source records as a flat list. Shape validation
-- happens afterwards in 'requireDataAndFileRecords'; this function
-- is intentionally permissive over the wire so that off-spec shapes
-- can be reported with structured 'UnsupportedXDelta1Shape' rather
-- than as bare Get-monad failures.
parseSourceList :: Int -> Get [ParsedSourceRecord]
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
  [first, second] -> case (parsedSourceWireKind first, parsedSourceWireKind second) of
    (WireKindData, WireKindFile) -> Right ParsedSourcePair
      { parsedDataRecord = first
      , parsedFileRecord = second
      }
    (WireKindData, WireKindData) -> shapeError "[data, data]"
    (WireKindFile, WireKindData) -> shapeError "[file, data]"
    (WireKindFile, WireKindFile) -> shapeError "[file, file]"
  []        -> shapeError "0 sources"
  [single]  -> shapeError ("1 source: " ++ wireKindLabel (parsedSourceWireKind single))
  many      -> shapeError (show (length many) ++ " sources")
  where
    shapeError description = Left (UnsupportedXDelta1Shape description)
    wireKindLabel WireKindData = "data"
    wireKindLabel WireKindFile = "file"

-- | Wrap a 'ParsedSourcePair' into the public 'XDelta1Sources'
-- record, folding the patch-level verification posture into each
-- source's MD5 field. Under 'VerifyAgainstStoredMD5s', per-source
-- MD5s survive as @Just@; under 'CreatorOptedOutOfVerification',
-- the parsed bytes are discarded (the curio-warning consults them
-- separately) and the field becomes @Nothing@.
applyPostureToSources :: XDelta1VerificationPosture -> ParsedSourcePair -> XDelta1Sources
applyPostureToSources posture sourcePair = XDelta1Sources
  { xdelta1DataSource = assembleSourceRecord posture (parsedDataRecord sourcePair)
  , xdelta1FileSource = assembleSourceRecord posture (parsedFileRecord sourcePair)
  }
  where
    assembleSourceRecord :: XDelta1VerificationPosture -> ParsedSourceRecord -> XDelta1Source
    assembleSourceRecord postureArg rec = XDelta1Source
      { xdelta1SourceName       = parsedSourceName rec
      , xdelta1SourceMD5        = case postureArg of
          VerifyAgainstStoredMD5s _      -> Just (parsedSourceMD5 rec)
          CreatorOptedOutOfVerification  -> Nothing
      , xdelta1SourceLength     = parsedSourceLength rec
      , xdelta1SourceOffsetMode = parsedSourceOffsetMode rec
      }

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

parseInstructions :: Int -> Get [ParsedInstruction]
parseInstructions 0 = pure []
parseInstructions count = do
  wireIndex <- edsioVarint
  offset <- Offset . fromIntegral <$> edsioVarint
  instructionLength <- FileSize . fromIntegral <$> edsioVarint
  rest <- parseInstructions (count - 1)
  pure (ParsedInstruction wireIndex offset instructionLength : rest)

-- | When a source uses sequential-offset mode, on-wire instruction
-- offsets are zero and the real offset is the running total of all
-- preceding instructions' lengths against that source. Looks up the
-- two sources' offset modes once, then folds across instructions
-- maintaining a per-target running position.
fixSequentialOffsets :: XDelta1Sources -> [XDelta1Instruction] -> [XDelta1Instruction]
fixSequentialOffsets sources instructions =
  reverse (snd (foldl' resolveSequentialOffset (initialPositions, []) instructions))
  where
    dataIsSequential = xdelta1SourceOffsetMode (xdelta1DataSource sources) == SequentialOffsets
    fileIsSequential = xdelta1SourceOffsetMode (xdelta1FileSource sources) == SequentialOffsets

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
