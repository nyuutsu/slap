{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.XDelta1
  ( XDelta1Patch(..)
  , XD1Source(..)
  , XD1Instruction(..)
  , parseXDelta1
  , applyXDelta1
  , xdelta1Info
  ) where

import Patch.Binary (getWord32BE, copyBSRange)
import Patch.Format (padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), (.|.), shiftL, shiftR, testBit)
import Data.Int (Int64)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)

import qualified Codec.Compression.GZip as GZip

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data XDelta1Patch = XDelta1Patch
  { xd1FromName     :: ByteString
  , xd1ToName       :: ByteString
  , xd1ToMD5        :: ByteString  -- 16 bytes
  , xd1ToLen        :: Int64
  , xd1Sources      :: [XD1Source]
  , xd1Instructions :: [XD1Instruction]
  , xd1DataSeg      :: ByteString  -- decompressed literal data
  } deriving (Show)

data XD1Source = XD1Source
  { xd1SrcName       :: ByteString
  , xd1SrcMD5        :: ByteString  -- 16 bytes
  , xd1SrcLen        :: Int64
  , xd1SrcIsData     :: Bool
  , xd1SrcSequential :: Bool
  } deriving (Show)

data XD1Instruction = XD1Instruction
  { xd1InstIndex  :: Int64
  , xd1InstOffset :: Int64
  , xd1InstLength :: Int64
  } deriving (Show)

----------------------------------------------------------------------------
-- EDSIO variable-length unsigned int (LEB128-like)
-- 7 bits per byte, LSB first, high bit = continuation
----------------------------------------------------------------------------

getEdsioVarint :: Int -> ByteString -> (Int64, Int)
getEdsioVarint off bs = go off 0 0
  where
    go i acc shift =
      let byte = BS.index bs i
          val = fromIntegral (byte .&. 0x7F) :: Int64
          acc' = acc .|. (val `shiftL` shift)
      in if testBit byte 7
         then go (i + 1) acc' (shift + 7)
         else (acc', i - off + 1)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseXDelta1 :: ByteString -> Either String XDelta1Patch
parseXDelta1 bs
  | BS.length bs < 20 = Left "too short for xdelta1"
  | magic == "%XDZ004%" = parseV11 bs magic  -- v1.1
  | magic == "%XDZ003%" = parseV11 bs magic  -- v1.0.4
  | magic == "%XDZ002%" = Left "xdelta v1.0 format not supported"
  | BS.take 7 bs == "%XDELTA" = Left "xdelta v0.14 format not supported"
  | otherwise = Left "not an xdelta1 file (bad magic)"
  where
    magic = BS.take 8 bs

parseV11 :: ByteString -> ByteString -> Either String XDelta1Patch
parseV11 bs expectedMagic
  | totalLen < 44 = Left "xdelta1: file too short"
  | trailingMagic /= expectedMagic = Left "xdelta1: trailing magic mismatch"
  | otherwise = parseControl ctrlSeg dataSeg fromName toName
  where
    totalLen = BS.length bs

    -- Header: 6 x uint32 BE at offset 8
    flags    = getWord32BE 8 bs
    nameLens = getWord32BE 12 bs
    fromNameLen = fromIntegral (nameLens `shiftR` 16) :: Int
    toNameLen   = fromIntegral (nameLens .&. 0xFFFF) :: Int
    fromName = BS.take fromNameLen (BS.drop 32 bs)
    toName   = BS.take toNameLen (BS.drop (32 + fromNameLen) bs)
    headerOff = 32 + fromNameLen + toNameLen

    -- Trailer: last 12 bytes = control_offset (4B) + magic (8B)
    trailerOff    = totalLen - 12
    controlOff    = fromIntegral (getWord32BE trailerOff bs) :: Int
    trailingMagic = BS.take 8 (BS.drop (totalLen - 8) bs)

    -- Decompress segments if FLAG_PATCH_COMPRESSED (bit 3)
    compressed = testBit flags 3
    dataSegRaw = BS.take (controlOff - headerOff) (BS.drop headerOff bs)
    ctrlSegRaw = BS.take (trailerOff - controlOff) (BS.drop controlOff bs)
    dataSeg = if compressed then decompressGzip dataSegRaw else dataSegRaw
    ctrlSeg = if compressed then decompressGzip ctrlSegRaw else ctrlSegRaw

decompressGzip :: ByteString -> ByteString
decompressGzip bs
  | BS.null bs = BS.empty
  | otherwise  = BL.toStrict $ GZip.decompress $ BL.fromStrict bs

-- | Parse the EDSIO-serialized XdeltaControl from the control segment.
parseControl :: ByteString -> ByteString -> ByteString -> ByteString
             -> Either String XDelta1Patch
parseControl ctrl dataSeg fromName toName
  | BS.length ctrl < 28 = Left "xdelta1: control segment too short"
  | otherwise =
      -- Type tag (uint32 BE) + allocation (uint32 BE, deprecated) = 8 bytes
      let pos0 = 8

          -- to_md5: 16 bytes
          toMD5 = BS.take 16 (BS.drop pos0 ctrl)
          pos1 = pos0 + 16

          -- to_len: varint
          (toLen, n1) = getEdsioVarint pos1 ctrl
          pos2 = pos1 + n1

          -- has_data: 1 byte boolean
          pos3 = pos2 + 1

          -- source_info array: varint count, then entries
          (srcCount, n2) = getEdsioVarint pos3 ctrl
          pos4 = pos3 + n2
          (sources, pos5) = parseSources (fromIntegral srcCount) pos4 ctrl

          -- instruction array: varint count, then entries
          (instCount, n3) = getEdsioVarint pos5 ctrl
          pos6 = pos5 + n3
          (insts, _) = parseInstructions (fromIntegral instCount) pos6 ctrl

          -- Reconstruct sequential source offsets
          fixedInsts = fixSequentialOffsets sources insts

      in Right (XDelta1Patch fromName toName toMD5 toLen sources fixedInsts dataSeg)

parseSources :: Int -> Int -> ByteString -> ([XD1Source], Int)
parseSources 0 pos _ = ([], pos)
parseSources n pos bs =
  let -- name: string = varint length + bytes
      (nameLen, n1) = getEdsioVarint pos bs
      pos1 = pos + n1
      name = BS.take (fromIntegral nameLen) (BS.drop pos1 bs)
      pos2 = pos1 + fromIntegral nameLen
      -- md5: 16 bytes
      md5 = BS.take 16 (BS.drop pos2 bs)
      pos3 = pos2 + 16
      -- len: varint
      (len, n2) = getEdsioVarint pos3 bs
      pos4 = pos3 + n2
      -- isdata: 1 byte boolean
      isdata = BS.index bs pos4 /= 0
      -- sequential: 1 byte boolean
      sequential = BS.index bs (pos4 + 1) /= 0
      pos5 = pos4 + 2
      src = XD1Source name md5 len isdata sequential
      (rest, posEnd) = parseSources (n - 1) pos5 bs
  in (src : rest, posEnd)

parseInstructions :: Int -> Int -> ByteString -> ([XD1Instruction], Int)
parseInstructions 0 pos _ = ([], pos)
parseInstructions n pos bs =
  let (idx, n1) = getEdsioVarint pos bs
      (off, n2) = getEdsioVarint (pos + n1) bs
      (len, n3) = getEdsioVarint (pos + n1 + n2) bs
      inst = XD1Instruction idx off len
      (rest, posEnd) = parseInstructions (n - 1) (pos + n1 + n2 + n3) bs
  in (inst : rest, posEnd)

-- | When a source has sequential=True, wire offsets are 0.
-- Reconstruct by maintaining a running position per source.
fixSequentialOffsets :: [XD1Source] -> [XD1Instruction] -> [XD1Instruction]
fixSequentialOffsets sources = reverse . snd . foldl' step (positions, [])
  where
    positions = replicate (length sources) (0 :: Int64)
    step (pos, acc) inst =
      let idx = fromIntegral (xd1InstIndex inst) :: Int
      in if idx < length sources && xd1SrcSequential (sources !! idx)
         then let off = pos !! idx
                  pos' = take idx pos ++ [off + xd1InstLength inst] ++ drop (idx + 1) pos
              in (pos', inst { xd1InstOffset = off } : acc)
         else (pos, inst : acc)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyXDelta1 :: XDelta1Patch -> ByteString -> Either String ByteString
applyXDelta1 patch _source
  | xd1ToLen patch == 0 = Right BS.empty
applyXDelta1 patch source = Right $ unsafeCreate sz $ \ptr ->
    go ptr 0 (xd1Instructions patch)
  where
    sz      = fromIntegral (xd1ToLen patch)
    srcList = xd1Sources patch
    dataSeg = xd1DataSeg patch

    go :: Ptr Word8 -> Int -> [XD1Instruction] -> IO ()
    go _ptr _pos [] = pure ()
    go ptr pos (inst:rest) = do
      let idx = fromIntegral (xd1InstIndex inst) :: Int
          srcBs = if idx < length srcList && xd1SrcIsData (srcList !! idx)
                  then dataSeg
                  else source
          off = fromIntegral (xd1InstOffset inst)
          len = fromIntegral (xd1InstLength inst) :: Int
      copyBSRange ptr pos srcBs off len
      go ptr (pos + len) rest

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

xdelta1Info :: XDelta1Patch -> String
xdelta1Info p = unlines $ filter (not . null)
  [ "format:      xdelta1"
  , "from:        " ++ BS8.unpack (xd1FromName p)
  , "to:          " ++ BS8.unpack (xd1ToName p)
  , "target size: " ++ show (xd1ToLen p)
  , "target MD5:  " ++ md5Hex (xd1ToMD5 p)
  , "sources:     " ++ show (length (xd1Sources p))
  , srcLines
  , "instructions:" ++ show (length (xd1Instructions p))
  , "data seg:    " ++ show (BS.length (xd1DataSeg p)) ++ " bytes"
  ]
  where
    md5Hex = concatMap (\b -> padHex 2 (fromIntegral b)) . BS.unpack
    srcLines = unlines
      [ "  [" ++ show i ++ "] " ++ BS8.unpack (xd1SrcName s)
        ++ (if xd1SrcIsData s then " (data)" else " (file)")
        ++ (if xd1SrcSequential s then " seq" else "")
        ++ "  " ++ show (xd1SrcLen s) ++ " bytes"
      | (i, s) <- zip [(0::Int)..] (xd1Sources p) ]

