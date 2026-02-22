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
import Patch.Get (Get, runGet, getByte, getBytes, skip, edsioVarint)
import Patch.Format (padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), shiftR, testBit)
import Data.Int (Int64)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)

import qualified Data.IntMap.Strict as IM
import qualified Data.IntSet as IS
import qualified Codec.Compression.GZip as GZip
import Control.Exception (SomeException, try, evaluate)
import System.IO.Unsafe (unsafePerformIO)

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
-- Parsing
----------------------------------------------------------------------------

parseXDelta1 :: ByteString -> Either String XDelta1Patch
parseXDelta1 bs
  | BS.length bs < 20 = Left "xdelta1: input too short"
  | magic == "%XDZ004%" = parseV11 bs magic  -- v1.1
  | magic == "%XDZ003%" = parseV11 bs magic  -- v1.0.4
  | magic == "%XDZ002%" = Left "xdelta1: unsupported version (v1.0)"
  | BS.take 7 bs == "%XDELTA" = Left "xdelta1: unsupported version (v0.14)"
  | otherwise = Left "not an xdelta1 file (bad magic)"
  where
    magic = BS.take 8 bs

parseV11 :: ByteString -> ByteString -> Either String XDelta1Patch
parseV11 bs expectedMagic
  | totalLen < 44 = Left "xdelta1: input too short"
  | trailingMagic /= expectedMagic = Left ("xdelta1: trailing magic mismatch (expected " ++ show expectedMagic ++ ", got " ++ show trailingMagic ++ ")")
  | otherwise = do
      dataSeg' <- safeDecompressGZip dataSegRaw
      ctrlSeg' <- safeDecompressGZip ctrlSegRaw
      parseControl ctrlSeg' dataSeg' fromName toName
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

    safeDecompressGZip raw
      | not compressed = Right raw
      | BS.null raw    = Right BS.empty
      | otherwise      = unsafePerformIO $ do
          result <- try @SomeException $ evaluate $ BL.toStrict $
                      BL.take maxDecompressedSize $
                      GZip.decompress $ BL.fromStrict raw
          pure $ case result of
            Left e  -> Left ("xdelta1: gzip decompression failed: " ++ show e)
            Right d -> Right d

    maxDecompressedSize = 4 * 1024 * 1024 * 1024 :: Int64  -- 4 GiB

-- | Parse the EDSIO-serialized XdeltaControl from the control segment.
parseControl :: ByteString -> ByteString -> ByteString -> ByteString
             -> Either String XDelta1Patch
parseControl ctrl dataSeg fromName toName
  | BS.length ctrl < 28 = Left ("xdelta1: truncated control segment (need 28 bytes, have " ++ show (BS.length ctrl) ++ ")")
  | otherwise = runGet parseCtrl ctrl
  where
    parseCtrl :: Get XDelta1Patch
    parseCtrl = do
      skip 8  -- type tag + allocation (deprecated)
      toMD5 <- getBytes 16
      toLen <- edsioVarint
      skip 1  -- has_data boolean
      srcCount <- fromIntegral <$> edsioVarint
      sources <- parseSources srcCount
      instCount <- fromIntegral <$> edsioVarint
      insts <- parseInstructions instCount
      let fixedInsts = fixSequentialOffsets sources insts
      pure (XDelta1Patch fromName toName toMD5 toLen sources fixedInsts dataSeg)

parseSources :: Int -> Get [XD1Source]
parseSources 0 = pure []
parseSources n = do
  nameLen <- fromIntegral <$> edsioVarint
  name <- getBytes nameLen
  md5 <- getBytes 16
  len <- edsioVarint
  isdata <- (/= 0) <$> getByte
  sequential <- (/= 0) <$> getByte
  rest <- parseSources (n - 1)
  pure (XD1Source name md5 len isdata sequential : rest)

parseInstructions :: Int -> Get [XD1Instruction]
parseInstructions 0 = pure []
parseInstructions n = do
  idx <- edsioVarint
  off <- edsioVarint
  len <- edsioVarint
  rest <- parseInstructions (n - 1)
  pure (XD1Instruction idx off len : rest)

-- | When a source has sequential=True, wire offsets are 0.
-- Reconstruct by maintaining a running position per source.
fixSequentialOffsets :: [XD1Source] -> [XD1Instruction] -> [XD1Instruction]
fixSequentialOffsets sources = reverse . snd . foldl' step (initPos, [])
  where
    seqIndices = IS.fromList [i | (i, s) <- zip [0..] sources, xd1SrcSequential s]
    initPos    = IM.fromList [(i, 0 :: Int64) | i <- IS.toList seqIndices]
    step (pos, acc) inst =
      let idx = fromIntegral (xd1InstIndex inst) :: Int
      in if IS.member idx seqIndices
         then let off  = IM.findWithDefault 0 idx pos
                  pos' = IM.insert idx (off + xd1InstLength inst) pos
              in (pos', inst { xd1InstOffset = off } : acc)
         else (pos, inst : acc)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyXDelta1 :: XDelta1Patch -> ByteString -> Either String ByteString
applyXDelta1 patch _source
  | xd1ToLen patch == 0 = Right BS.empty
  | xd1ToLen patch < 0  = Left "xdelta1: negative target size"
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
          -- Clamp to remaining output buffer
          safeLen = max 0 $ min len (sz - pos)
          -- Clamp source read to available data
          srcSafeLen = if off >= 0 && off < BS.length srcBs
                       then min safeLen (BS.length srcBs - off)
                       else 0
      copyBSRange ptr pos srcBs off srcSafeLen
      go ptr (pos + safeLen) rest

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
