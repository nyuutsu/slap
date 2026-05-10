{-# LANGUAGE OverloadedStrings #-}

module Slap.XDelta1.Parse
  ( parseXDelta1
  , parseVersion1Point1
  , parseControl
  , parseOneSource
  , parseInstructions
  , classifyXDelta1Shape
  , validateInstructionIndices
  , fixSequentialOffsets
    -- * Role newtypes for parseControl arguments
  , XDelta1ControlSegment(..)
  , XDelta1DataSegment(..)
  , XDelta1FromName(..)
  , XDelta1ToName(..)
  ) where

-- Canonical reference: tools/xdelta1/xdelta-1.1.4/ (xdelta 1.x source)

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..)
    , XDelta1SourceKind(..), XDelta1OffsetMode(..)
    , XDelta1SourceShape(..)
    , xdelta1TrailerSize
    )
import Slap.Binary (getWord32BE)
import Slap.Checksum (MD5Hash(..))
import Slap.Error (SlapError(..), DecompressionFailure(..), Parsed(..))
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
import Data.Foldable (traverse_)
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

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseXDelta1 :: PatchFileContents -> Either SlapError (Parsed XDelta1Patch)
parseXDelta1 patchContents@(PatchFileContents input)
  | ByteString.length input < 20 = Left (InputTooShort LabelXDelta1 (RequiredLength (Length 20)) (ActualLength (Length (ByteString.length input))))
  | magic == "%XDZ004%" = wrapParsed (parseVersion1Point1 patchContents (ExpectedMagic magic))
  | magic == "%XDZ003%" = Left (UnsupportedSubformat LabelXDelta1 "version 1.0.4")
  | magic == "%XDZ002%" = Left (UnsupportedSubformat LabelXDelta1 "version 1.0")
  | ByteString.take 7 input == "%XDELTA" = Left (UnsupportedSubformat LabelXDelta1 "version 0.14")
  | otherwise = Left (BadMagic LabelXDelta1 (ActualMagic (ByteString.take 8 input)))
  where
    magic = ByteString.take 8 input
    wrapParsed = fmap (\patch -> Parsed patch [])

-- | Body parser for @%XDZ004%@ (xdelta 1.1.x), the only xdelta1 era
-- slap currently supports. Sibling body parsers for other eras
-- (1.0.4 under @%XDZ003%@, 1.0.x under @%XDZ002%@) would live
-- alongside this one and be dispatched to by 'parseXDelta1'.
parseVersion1Point1 :: PatchFileContents -> ExpectedMagic -> Either SlapError XDelta1Patch
parseVersion1Point1 (PatchFileContents input) expectedMagic
  | totalLength < 44 = Left (InputTooShort LabelXDelta1 (RequiredLength (Length 44)) (ActualLength (Length totalLength)))
  | trailingMagic /= unExpectedMagic expectedMagic = Left (TrailingMagicMismatch LabelXDelta1 expectedMagic (ActualMagic trailingMagic))
  | otherwise = do
      decompressedData    <- safeDecompressGZip dataSegmentRaw
      decompressedControl <- safeDecompressGZip controlSegmentRaw
      parseControl (XDelta1ControlSegment decompressedControl)
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
    compressed = testBit flags 3
    dataSegmentRaw = ByteString.take (controlOffset - headerOffset) (ByteString.drop headerOffset input)
    controlSegmentRaw = ByteString.take (trailerOffset - controlOffset) (ByteString.drop controlOffset input)

    safeDecompressGZip raw
      | not compressed = Right raw
      | ByteString.null raw    = Right ByteString.empty
      | otherwise      = case gzipInflate raw of
          Left cause   -> Left (DecompressionFailed (XDelta1Failed cause))
          Right result -> Right result

-- | Parse the EDSIO-serialized XdeltaControl from the control segment.
-- Source list is parsed raw and then classified into one of the four
-- spec-permitted shapes by 'classifyXDelta1Shape'; any off-spec count
-- or ordering is rejected with 'UnsupportedXDelta1Shape' before the
-- patch record is constructed. Instructions are then validated against
-- the shape's index range with 'validateInstructionIndices'. Only after
-- both checks pass do sequential offsets get resolved and the
-- 'XDelta1Patch' record assembled.
parseControl :: XDelta1ControlSegment
             -> XDelta1DataSegment
             -> XDelta1FromName
             -> XDelta1ToName
             -> Either SlapError XDelta1Patch
parseControl controlSegment dataSegment fromName toName
  | ByteString.length controlBytes < 28 = Left (TruncatedRecord LabelXDelta1 0 (Length 28) (Length (ByteString.length controlBytes)))
  | otherwise = do
      (toMD5, targetLength, rawSources, rawInstructions) <-
        case runGet parseControlBody controlBytes of
          Left errorMessage -> Left (ParseError LabelXDelta1 errorMessage)
          Right result      -> Right result
      sourceShape <- classifyXDelta1Shape rawSources
      validateInstructionIndices sourceShape rawInstructions
      let fixedInstructions = fixSequentialOffsets sourceShape rawInstructions
      Right (XDelta1Patch fromNameBytes toNameBytes
                          toMD5 targetLength sourceShape
                          fixedInstructions dataBytes)
  where
    controlBytes  = unXDelta1ControlSegment controlSegment
    dataBytes     = unXDelta1DataSegment    dataSegment
    fromNameBytes = unXDelta1FromName       fromName
    toNameBytes   = unXDelta1ToName         toName

    parseControlBody :: Get (MD5Hash, FileSize, [XDelta1Source], [XDelta1Instruction])
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

-- | Parse a single EDSIO-serialized 'XDelta1Source' record.
parseOneSource :: Get XDelta1Source
parseOneSource = do
  nameLength <- fromIntegral <$> edsioVarint
  sourceName <- getBytes (Length nameLength)
  md5Bytes <- MD5Hash <$> getBytes (Length 16)
  sourceLength <- edsioVarint
  sourceKindByte <- getByte
  offsetModeByte <- getByte
  let sourceKind = if sourceKindByte /= 0 then DataSegmentSource else FileSource
      offsetMode = if offsetModeByte /= 0 then SequentialOffsets else AbsoluteOffsets
  pure (XDelta1Source sourceName md5Bytes (FileSize (fromIntegral sourceLength)) sourceKind offsetMode)

-- | Parse @count@ source records as a flat list. Shape validation
-- happens afterwards in 'classifyXDelta1Shape'; this function is
-- intentionally permissive over the wire so that off-spec shapes
-- can be reported with structured 'UnsupportedXDelta1Shape' rather
-- than as bare Get-monad failures.
parseSourceList :: Int -> Get [XDelta1Source]
parseSourceList 0 = pure []
parseSourceList count = do
  source <- parseOneSource
  rest <- parseSourceList (count - 1)
  pure (source : rest)

-- | Classify a raw source list into one of the four
-- 'XDelta1SourceShape' constructors, or refuse with a structured
-- 'UnsupportedXDelta1Shape' error. The four legal shapes are:
--
--   * @[]@                                — 'XDelta1NoSources'
--   * @[DataSegmentSource]@               — 'XDelta1DataOnly'
--   * @[FileSource]@                      — 'XDelta1FileOnly'
--   * @[DataSegmentSource, FileSource]@   — 'XDelta1DataAndFile'
--
-- Any other count or ordering is off-spec; the 'String' carried by
-- 'UnsupportedXDelta1Shape' names the offending input
-- ("3 sources", "[file, data]", "[file, file]", etc.) so the
-- diagnostic reads cleanly without needing a separate render arm.
classifyXDelta1Shape :: [XDelta1Source] -> Either SlapError XDelta1SourceShape
classifyXDelta1Shape sources = case sources of
  []        -> Right XDelta1NoSources
  [single]  -> case xdelta1SourceKind single of
    DataSegmentSource -> Right (XDelta1DataOnly single)
    FileSource        -> Right (XDelta1FileOnly single)
  [first, second] -> case (xdelta1SourceKind first, xdelta1SourceKind second) of
    (DataSegmentSource, FileSource)        -> Right (XDelta1DataAndFile first second)
    (DataSegmentSource, DataSegmentSource) -> shapeError "[data, data]"
    (FileSource,        DataSegmentSource) -> shapeError "[file, data]"
    (FileSource,        FileSource)        -> shapeError "[file, file]"
  many -> shapeError (show (length many) ++ " sources")
  where
    shapeError description = Left (UnsupportedXDelta1Shape description)

-- | Reject any instruction whose source index falls outside the
-- declared shape's range. With 'XDelta1NoSources' there are no
-- valid indices; with 'XDelta1DataOnly' or 'XDelta1FileOnly' only
-- index 0 is valid; with 'XDelta1DataAndFile' indices 0 and 1 are
-- valid. The shape constructor IS the validity proof: out-of-range
-- indices are caught here at parse rather than as bounds-check
-- masking at apply time.
validateInstructionIndices :: XDelta1SourceShape -> [XDelta1Instruction] -> Either SlapError ()
validateInstructionIndices shape = traverse_ checkOne
  where
    maxValidIndex :: Int64
    maxValidIndex = case shape of
      XDelta1NoSources       -> -1   -- no valid indices at all
      XDelta1DataOnly _      -> 0
      XDelta1FileOnly _      -> 0
      XDelta1DataAndFile _ _ -> 1
    checkOne instruction =
      let idx = xdelta1InstructionIndex instruction
      in if idx >= 0 && idx <= maxValidIndex
           then Right ()
           else Left (XDelta1InstructionIndexOutOfRange idx shape)

parseInstructions :: Int -> Get [XDelta1Instruction]
parseInstructions 0 = pure []
parseInstructions count = do
  index <- edsioVarint
  offset <- Offset . fromIntegral <$> edsioVarint
  instructionLength <- FileSize . fromIntegral <$> edsioVarint
  rest <- parseInstructions (count - 1)
  pure (XDelta1Instruction index offset instructionLength : rest)

-- | When a source uses sequential-offset mode, on-wire instruction
-- offsets are zero and the real offset is the running total of all
-- preceding instructions' lengths against that source. Walks the
-- shape (one or two sources, never more) to find sequential-mode
-- indices, then folds across instructions advancing per-index
-- running positions. The shape walk replaces the prior @zip [0..]
-- sources@ enumeration; per-instruction logic is unchanged.
fixSequentialOffsets :: XDelta1SourceShape -> [XDelta1Instruction] -> [XDelta1Instruction]
fixSequentialOffsets shape instructions =
  reverse (snd (foldl' resolveSequentialOffset (initialPositions, []) instructions))
  where
    sequentialIndexedSources :: [(Int64, XDelta1Source)]
    sequentialIndexedSources = case shape of
      XDelta1NoSources                            -> []
      XDelta1DataOnly source                      -> [(0, source)]
      XDelta1FileOnly source                      -> [(0, source)]
      XDelta1DataAndFile dataSrc fileSrc          -> [(0, dataSrc), (1, fileSrc)]

    -- Sources with sequential-offset mode, paired with their initial
    -- (zero) running position.
    initialPositions :: [(Int64, Int)]
    initialPositions =
      [ (idx, 0)
      | (idx, source) <- sequentialIndexedSources
      , xdelta1SourceOffsetMode source == SequentialOffsets
      ]

    resolveSequentialOffset (positions, accumulated) instruction =
      let idx = xdelta1InstructionIndex instruction
      in case lookup idx positions of
           Nothing       -> (positions, instruction : accumulated)
           Just rawOffset ->
             let advanced = rawOffset + unFileSize (xdelta1InstructionLength instruction)
                 updated  = updateAssoc idx advanced positions
             in ( updated
                , instruction { xdelta1InstructionOffset = Offset rawOffset } : accumulated
                )

    updateAssoc :: Int64 -> Int -> [(Int64, Int)] -> [(Int64, Int)]
    updateAssoc _   _      []                          = []
    updateAssoc key newVal ((k, v):rest)
      | k == key  = (k, newVal) : rest
      | otherwise = (k, v)      : updateAssoc key newVal rest
