{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.XDelta1
  ( XDelta1Patch(..)
  , XDelta1Source(..)
  , XDelta1Instruction(..)
  , parseXDelta1
  , applyXDelta1
  , xdelta1Meta
  , xdelta1Info
  ) where

-- Canonical reference: tools/xdelta1/xdelta-1.1.4/ (xdelta 1.x source)

import Patch.Binary (getWord32BE, copyByteStringRange)
import Patch.Get (Get, runGet, getByte, getBytes, skip, edsioVarint)
import Patch.Format (padHex, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), shiftR, testBit)
import Data.Int (Int64)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)

import qualified Data.IntMap.Strict as IntMap
import qualified Data.IntSet as IntSet
import Patch.Compress (gzipInflate)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data XDelta1Patch = XDelta1Patch
  { xdelta1Version      :: String      -- "1.1" or "1.0.4"
  , xdelta1FromName     :: ByteString
  , xdelta1ToName       :: ByteString
  , xdelta1ToMD5        :: ByteString  -- 16 bytes
  , xdelta1TargetLength :: Int64
  , xdelta1Sources      :: [XDelta1Source]
  , xdelta1Instructions :: [XDelta1Instruction]
  , xdelta1DataSegment  :: ByteString  -- decompressed literal data
  } deriving (Show)

data XDelta1Source = XDelta1Source
  { xdelta1SourceName       :: ByteString
  , xdelta1SourceMD5        :: ByteString  -- 16 bytes
  , xdelta1SourceLength     :: Int64
  , xdelta1SourceIsData     :: Bool
  , xdelta1SourceSequential :: Bool
  } deriving (Show)

data XDelta1Instruction = XDelta1Instruction
  { xdelta1InstructionIndex  :: Int64
  , xdelta1InstructionOffset :: Int64
  , xdelta1InstructionLength :: Int64
  } deriving (Show)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseXDelta1 :: ByteString -> Either String XDelta1Patch
parseXDelta1 input
  | ByteString.length input < 20 = Left "xdelta1: input too short"
  | magic == "%XDZ004%" = parseV11 input magic "1.1"
  | magic == "%XDZ003%" = parseV11 input magic "1.0.4"
  | magic == "%XDZ002%" = Left "xdelta1: unsupported version (v1.0)"
  | ByteString.take 7 input == "%XDELTA" = Left "xdelta1: unsupported version (v0.14)"
  | otherwise = Left "not an xdelta1 file (bad magic)"
  where
    magic = ByteString.take 8 input

parseV11 :: ByteString -> ByteString -> String -> Either String XDelta1Patch
parseV11 input expectedMagic version
  | totalLength < 44 = Left "xdelta1: input too short"
  | trailingMagic /= expectedMagic = Left ("xdelta1: trailing magic mismatch (expected " ++ show expectedMagic ++ ", got " ++ show trailingMagic ++ ")")
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
    trailerOffset = totalLength - 12
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
          Left _  -> Left "xdelta1: gzip decompression failed"
          Right result -> Right result

-- | Parse the EDSIO-serialized XdeltaControl from the control segment.
parseControl :: String -> ByteString -> ByteString -> ByteString -> ByteString
             -> Either String XDelta1Patch
parseControl version controlSegment dataSegment fromName toName
  | ByteString.length controlSegment < 28 = Left ("xdelta1: truncated control segment (need 28 bytes, have " ++ show (ByteString.length controlSegment) ++ ")")
  | otherwise = runGet parseControlBody controlSegment
  where
    parseControlBody :: Get XDelta1Patch
    parseControlBody = do
      skip 8  -- type tag + allocation (deprecated)
      toMD5 <- getBytes 16
      targetLength <- edsioVarint
      skip 1  -- has_data boolean
      sourceCount <- fromIntegral <$> edsioVarint
      sources <- parseSources sourceCount
      instructionCount <- fromIntegral <$> edsioVarint
      instructions <- parseInstructions instructionCount
      let fixedInstructions = fixSequentialOffsets sources instructions
      pure (XDelta1Patch version fromName toName toMD5 targetLength sources fixedInstructions dataSegment)

parseSources :: Int -> Get [XDelta1Source]
parseSources 0 = pure []
parseSources count = do
  nameLength <- fromIntegral <$> edsioVarint
  name <- getBytes nameLength
  md5 <- getBytes 16
  sourceLength <- edsioVarint
  isdata <- (/= 0) <$> getByte
  sequential <- (/= 0) <$> getByte
  rest <- parseSources (count - 1)
  pure (XDelta1Source name md5 sourceLength isdata sequential : rest)

parseInstructions :: Int -> Get [XDelta1Instruction]
parseInstructions 0 = pure []
parseInstructions count = do
  index <- edsioVarint
  offset <- edsioVarint
  instructionLength <- edsioVarint
  rest <- parseInstructions (count - 1)
  pure (XDelta1Instruction index offset instructionLength : rest)

-- | When a source has sequential=True, wire offsets are 0.
-- Reconstruct by maintaining a running position per source.
fixSequentialOffsets :: [XDelta1Source] -> [XDelta1Instruction] -> [XDelta1Instruction]
fixSequentialOffsets sources = reverse . snd . foldl' step (initialPositions, [])
  where
    sequentialIndices = IntSet.fromList [index | (index, entry) <- zip [0..] sources, xdelta1SourceSequential entry]
    initialPositions = IntMap.fromList [(index, 0 :: Int64) | index <- IntSet.toList sequentialIndices]
    step (positions, accumulated) instruction =
      let index = fromIntegral (xdelta1InstructionIndex instruction) :: Int
      in if IntSet.member index sequentialIndices
         then let offset          = IntMap.findWithDefault 0 index positions
                  updatedPositions = IntMap.insert index (offset + xdelta1InstructionLength instruction) positions
              in (updatedPositions, instruction { xdelta1InstructionOffset = offset } : accumulated)
         else (positions, instruction : accumulated)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyXDelta1 :: XDelta1Patch -> ByteString -> Either String ByteString
applyXDelta1 patch _source
  | xdelta1TargetLength patch == 0 = Right ByteString.empty
  | xdelta1TargetLength patch < 0  = Left "xdelta1: negative target size"
applyXDelta1 patch source = Right $ unsafeCreate outputSize $ \targetPointer ->
    applyLoop targetPointer 0 (xdelta1Instructions patch)
  where
    outputSize = fromIntegral (xdelta1TargetLength patch)
    sourceList    = xdelta1Sources patch
    dataSegment    = xdelta1DataSegment patch

    applyLoop :: Ptr Word8 -> Int -> [XDelta1Instruction] -> IO ()
    applyLoop _targetPointer _position [] = pure ()
    applyLoop targetPointer position (instruction:rest) = do
      let index = fromIntegral (xdelta1InstructionIndex instruction) :: Int
          sourceBytes = if index < length sourceList && xdelta1SourceIsData (sourceList !! index)
                        then dataSegment
                        else source
          instructionOffset = fromIntegral (xdelta1InstructionOffset instruction)
          instructionLength = fromIntegral (xdelta1InstructionLength instruction) :: Int
          -- Clamp to remaining output buffer
          safeLength = max 0 $ min instructionLength (outputSize - position)
          -- Clamp source read to available data
          sourceSafeLength = if instructionOffset >= 0 && instructionOffset < ByteString.length sourceBytes
                             then min safeLength (ByteString.length sourceBytes - instructionOffset)
                             else 0
      copyByteStringRange targetPointer position sourceBytes instructionOffset sourceSafeLength
      applyLoop targetPointer (position + safeLength) rest

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

xdelta1Meta :: XDelta1Patch -> [(String, String)]
xdelta1Meta patch =
  [ ("version", xdelta1Version patch) ]
  ++ [ ("from", ByteString8.unpack (xdelta1FromName patch))
     , ("to", ByteString8.unpack (xdelta1ToName patch))
     , ("target size", show (xdelta1TargetLength patch))
     , ("target MD5", md5Hex (xdelta1ToMD5 patch))
     , ("sources", show (length sources))
     ]
  ++ sourceMD5s
  ++ [ ("data seg", show (ByteString.length (xdelta1DataSegment patch)) ++ " bytes") ]
  where
    sources = xdelta1Sources patch
    md5Hex = concatMap (\byte -> padHex 2 (fromIntegral byte)) . ByteString.unpack
    sourceMD5s
      | [entry] <- sources = [("source MD5", md5Hex (xdelta1SourceMD5 entry))]
      | otherwise       = [("source " ++ show index ++ " MD5", md5Hex (xdelta1SourceMD5 entry))
                            | (index, entry) <- zip [(1::Int)..] sources]

xdelta1Info :: XDelta1Patch -> String
xdelta1Info patch = unlines $ filter (not . null) $
  [ "format:      xdelta1 v" ++ xdelta1Version patch ]
  ++ map renderField (xdelta1Meta patch)
  ++ [ sourceLines
     , "instructions:" ++ show (length (xdelta1Instructions patch))
     ]
  where
    sourceLines = unlines
      [ "  [" ++ show index ++ "] " ++ ByteString8.unpack (xdelta1SourceName entry)
        ++ (if xdelta1SourceIsData entry then " (data)" else " (file)")
        ++ (if xdelta1SourceSequential entry then " seq" else "")
        ++ "  " ++ show (xdelta1SourceLength entry) ++ " bytes"
        ++ "  MD5:" ++ md5Hex (xdelta1SourceMD5 entry)
      | (index, entry) <- zip [(0::Int)..] (xdelta1Sources patch) ]
    md5Hex = concatMap (\byte -> padHex 2 (fromIntegral byte)) . ByteString.unpack
