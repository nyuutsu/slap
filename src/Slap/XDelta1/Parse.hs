{-# LANGUAGE OverloadedStrings #-}

module Slap.XDelta1.Parse
  ( parseXDelta1
  , parseV11
  , parseControl
  , parseSources
  , parseInstructions
  , fixSequentialOffsets
  ) where

-- Canonical reference: tools/xdelta1/xdelta-1.1.4/ (xdelta 1.x source)

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..)
    , XDelta1Version(..), XDelta1SourceKind(..), XDelta1OffsetMode(..)
    , xdelta1TrailerSize
    )
import Slap.Binary (getWord32BE)
import Slap.Checksum (MD5Hash(..))
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, skip, edsioVarint)
import Slap.Measure (Length(..), FileSize(..), Offset(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ExpectedMagic(..))
import Slap.Compress (gzipInflate)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), shiftR, testBit)

import qualified Data.IntMap.Strict as IntMap
import qualified Data.IntSet as IntSet

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseXDelta1 :: ByteString -> Either SlapError XDelta1Patch
parseXDelta1 input
  | ByteString.length input < 20 = Left (InputTooShort LabelXDelta1 (RequiredLength (Length 20)) (ActualLength (Length (ByteString.length input))))
  | magic == "%XDZ004%" = parseV11 input magic XDelta1v11
  | magic == "%XDZ003%" = parseV11 input magic XDelta1v104
  | magic == "%XDZ002%" = Left (UnsupportedSubformat LabelXDelta1 "v1.0")
  | ByteString.take 7 input == "%XDELTA" = Left (UnsupportedSubformat LabelXDelta1 "v0.14")
  | otherwise = Left (BadMagic LabelXDelta1 (ActualMagic (ByteString.take 8 input)))
  where
    magic = ByteString.take 8 input

parseV11 :: ByteString -> ByteString -> XDelta1Version -> Either SlapError XDelta1Patch
parseV11 input expectedMagic version
  | totalLength < 44 = Left (InputTooShort LabelXDelta1 (RequiredLength (Length 44)) (ActualLength (Length totalLength)))
  | trailingMagic /= expectedMagic = Left (TrailingMagicMismatch LabelXDelta1 (ExpectedMagic expectedMagic) (ActualMagic trailingMagic))
  | otherwise = do
      decompressedData    <- safeDecompressGZip dataSegmentRaw
      decompressedControl <- safeDecompressGZip controlSegmentRaw
      parseControl version decompressedControl decompressedData fromName toName
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
          Left _  -> Left (DecompressionFailed LabelXDelta1 "gzip")
          Right result -> Right result

-- | Parse the EDSIO-serialized XdeltaControl from the control segment.
parseControl :: XDelta1Version -> ByteString -> ByteString -> ByteString -> ByteString
             -> Either SlapError XDelta1Patch
parseControl version controlSegment dataSegment fromName toName
  | ByteString.length controlSegment < 28 = Left (TruncatedRecord LabelXDelta1 0 (Length 28) (Length (ByteString.length controlSegment)))
  | otherwise = case runGet parseControlBody controlSegment of
      Left errorMessage -> Left (ParseError LabelXDelta1 errorMessage)
      Right result -> Right result
  where
    parseControlBody :: Get XDelta1Patch
    parseControlBody = do
      skip (Length 8)  -- type tag + allocation (deprecated)
      toMD5 <- MD5Hash <$> getBytes (Length 16)
      targetLength <- edsioVarint
      skip (Length 1)  -- has_data boolean
      sourceCount <- fromIntegral <$> edsioVarint
      sources <- parseSources sourceCount
      instructionCount <- fromIntegral <$> edsioVarint
      instructions <- parseInstructions instructionCount
      let fixedInstructions = fixSequentialOffsets sources instructions
      pure (XDelta1Patch version fromName toName toMD5 (FileSize (fromIntegral targetLength)) sources fixedInstructions dataSegment)

parseSources :: Int -> Get [XDelta1Source]
parseSources 0 = pure []
parseSources count = do
  nameLength <- fromIntegral <$> edsioVarint
  sourceName <- getBytes (Length nameLength)
  md5Bytes <- MD5Hash <$> getBytes (Length 16)
  sourceLength <- edsioVarint
  sourceKindByte <- getByte
  offsetModeByte <- getByte
  let sourceKind = if sourceKindByte /= 0 then DataSegmentSource else FileSource
      offsetMode = if offsetModeByte /= 0 then SequentialOffsets else AbsoluteOffsets
  rest <- parseSources (count - 1)
  pure (XDelta1Source sourceName md5Bytes (FileSize (fromIntegral sourceLength)) sourceKind offsetMode : rest)

parseInstructions :: Int -> Get [XDelta1Instruction]
parseInstructions 0 = pure []
parseInstructions count = do
  index <- edsioVarint
  offset <- Offset . fromIntegral <$> edsioVarint
  instructionLength <- FileSize . fromIntegral <$> edsioVarint
  rest <- parseInstructions (count - 1)
  pure (XDelta1Instruction index offset instructionLength : rest)

-- | When a source has sequential offsets, wire offsets are 0.
-- Reconstruct by maintaining a running position per source.
fixSequentialOffsets :: [XDelta1Source] -> [XDelta1Instruction] -> [XDelta1Instruction]
fixSequentialOffsets sources = reverse . snd . foldl' resolveSequentialOffset (initialPositions, [])
  where
    sequentialIndices = IntSet.fromList [index | (index, entry) <- zip [0..] sources, xdelta1SourceOffsetMode entry == SequentialOffsets]
    initialPositions = IntMap.fromList [(index, 0 :: Int) | index <- IntSet.toList sequentialIndices]
    resolveSequentialOffset (positions, accumulated) instruction =
      let index = fromIntegral (xdelta1InstructionIndex instruction) :: Int
      in if IntSet.member index sequentialIndices
         then let rawOffset       = IntMap.findWithDefault 0 index positions
                  updatedPositions = IntMap.insert index (rawOffset + unFileSize (xdelta1InstructionLength instruction)) positions
              in (updatedPositions, instruction { xdelta1InstructionOffset = Offset rawOffset } : accumulated)
         else (positions, instruction : accumulated)
