{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.DPS
  ( DPSPatch(..)
  , DPSRecord(..)
  , DPSMode(..)
  , DPSPayload(..)
  , DPSStability(..)
  , parseDPS
  , applyDPS
  , createDPS
  , dpsMeta
  , dpsInfo
  , isDPS
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/DPS (format spec, from DPS patcher source)
-- Original C source: https://github.com/xperia64/android-rom-patcher/blob/master/jni/dpspatcher/dpspatcher.c
-- Author: Marc de Falco (Deufeufeu); deufeufeu.free.fr is dead.

import Patch.Get (Get, runGet, getByte, getBytes, remaining)
import qualified Patch.Get as G

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Patch.Binary (putWord32LE, diffHunks)
import Patch.Format (renderField)
import Data.Int (Int64)
import Data.Word (Word8, Word32)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data DPSStability = DPSStable | DPSUnstable
  deriving (Show, Eq)

toDPSStability :: Word8 -> Either String DPSStability
toDPSStability 0 = Right DPSStable
toDPSStability 1 = Right DPSUnstable
toDPSStability b = Left ("DPS: unknown stability flag: " ++ show b)

fromDPSStability :: DPSStability -> Word8
fromDPSStability DPSStable   = 0
fromDPSStability DPSUnstable = 1

data DPSPatch = DPSPatch
  { dpsName       :: ByteString   -- 64 bytes, null-padded
  , dpsAuthor     :: ByteString   -- 64 bytes, null-padded
  , dpsVersion    :: ByteString   -- 64 bytes, null-padded
  , dpsFlag       :: DPSStability
  , dpsDPSVersion :: Word8        -- must be 1
  , dpsOrigSize   :: Int64        -- original ROM size
  , dpsRecords    :: [DPSRecord]
  } deriving (Show)

data DPSMode = CopyFromROM | EnclosedData
  deriving (Show, Eq)

data DPSRecord = DPSRecord
  { dpsRecMode      :: DPSMode
  , dpsRecOutOffset :: Int64       -- write position in output
  , dpsRecPayload   :: DPSPayload
  } deriving (Show)

data DPSPayload
  = PayloadCopy Int64 Int64        -- source ROM offset, length
  | PayloadData ByteString         -- embedded data
  deriving (Show)

----------------------------------------------------------------------------
-- Detection heuristic (no magic bytes)
----------------------------------------------------------------------------

-- | Heuristic detection: DPS files have a 198-byte header with
-- printable ASCII in the first 192 bytes, version byte = 1 at
-- offset 193, flag byte 0 or 1 at offset 192.
isDPS :: ByteString -> Bool
isDPS bs
  | BS.length bs < 198 = False  -- 3×64 header + flag + version + u32 orig_size
  | BS.index bs 193 /= 1 = False  -- DPS version must be 1
  | BS.index bs 192 > 1 = False   -- stability flag must be 0 or 1
  | not (BS.all isHeaderByte (BS.take 192 bs)) = False
  -- Zero-record patch (198 bytes exactly) is valid: identity diff.
  -- When records exist, check the first mode byte for extra confidence.
  | BS.length bs > 198 = BS.index bs 198 <= 1
  | otherwise = True
  where
    isHeaderByte b = (b >= 0x20 && b <= 0x7E) || b == 0

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseDPS :: ByteString -> Either String DPSPatch
parseDPS bs
  | BS.length bs < 198 = Left "DPS: input too short"
  | BS.index bs 193 /= 1 = Left ("DPS: unsupported version byte: " ++ show (BS.index bs 193))
  | otherwise = runGet parseDPS' bs

parseDPS' :: Get DPSPatch
parseDPS' = do
  name    <- trimNull <$> getBytes 64
  author  <- trimNull <$> getBytes 64
  version <- trimNull <$> getBytes 64
  flagByte <- getByte
  case toDPSStability flagByte of
    Left err -> fail err
    Right flag -> do
      ver     <- getByte
      origSz  <- fromIntegral <$> G.word32LE
      recs    <- parseRecords
      pure DPSPatch
        { dpsName       = name
        , dpsAuthor     = author
        , dpsVersion    = version
        , dpsFlag       = flag
        , dpsDPSVersion = ver
        , dpsOrigSize   = origSz
        , dpsRecords    = recs
        }

parseRecords :: Get [DPSRecord]
parseRecords = do
  avail <- remaining
  if avail < 5 then pure []
  else do
    mode <- getByte
    outOff <- fromIntegral <$> G.word32LE
    -- UniPatcher wiki swaps mode descriptions; chunk structures are correct.
    payload <- case mode of
      0 -> do  -- CopyFromROM: read offset + length from patch
        srcOff <- fromIntegral <$> G.word32LE
        len    <- fromIntegral <$> G.word32LE
        pure (DPSRecord CopyFromROM outOff (PayloadCopy srcOff len))
      _ -> do  -- EnclosedData: read length + data from patch
        len  <- fromIntegral <$> G.word32LE :: Get Int
        dat  <- getBytes len
        pure (DPSRecord EnclosedData outOff (PayloadData dat))
    rest <- parseRecords
    pure (payload : rest)

trimNull :: ByteString -> ByteString
trimNull = BS.takeWhile (/= 0)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

-- | Apply a DPS patch. Builds output from source ROM + embedded data.
applyDPS :: DPSPatch -> ByteString -> Either String ByteString
applyDPS patch source = Right $ buildOutput source (dpsRecords patch)

buildOutput :: ByteString -> [DPSRecord] -> ByteString
buildOutput source recs =
  -- DPS builds output by writing chunks at specified offsets.
  -- Start with a copy of the source, then overlay records.
  let base = source
      apply1 buf (DPSRecord _ outOff (PayloadData dat)) =
        overlay buf (fromIntegral outOff) dat
      apply1 buf (DPSRecord _ outOff (PayloadCopy srcOff len)) =
        let chunk = safeTake (fromIntegral len) (fromIntegral srcOff) source
        in overlay buf (fromIntegral outOff) chunk
  in foldl' apply1 base recs

-- | Write bytes at a given offset, extending with zeros if needed.
overlay :: ByteString -> Int -> ByteString -> ByteString
overlay buf off dat
  | off + BS.length dat <= BS.length buf =
      let (before, rest) = BS.splitAt off buf
          after = BS.drop (BS.length dat) rest
      in before <> dat <> after
  | off <= BS.length buf =
      BS.take off buf <> dat
  | otherwise =
      buf <> BS.replicate (off - BS.length buf) 0 <> dat

-- | Safe slice from a ByteString, padding with zeros if out of range.
safeTake :: Int -> Int -> ByteString -> ByteString
safeTake len off bs
  | off >= BS.length bs = BS.replicate len 0
  | off + len > BS.length bs =
      let available = BS.take (BS.length bs - off) (BS.drop off bs)
      in available <> BS.replicate (len - BS.length available) 0
  | otherwise = BS.take len (BS.drop off bs)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

dpsMeta :: DPSPatch -> [(String, String)]
dpsMeta p = concat
  [ fieldPair "name"    (dpsName p)
  , fieldPair "author"  (dpsAuthor p)
  , fieldPair "version" (dpsVersion p)
  , [("orig size", show (dpsOrigSize p))]
  , [("flag", "unstable") | dpsFlag p == DPSUnstable]
  ]
  where
    fieldPair _ bs | BS.null bs = []
    fieldPair label bs = [(label, BS8.unpack bs)]

dpsInfo :: DPSPatch -> String
dpsInfo p = unlines $ filter (not . null) $
  [ "format:      DPS (Deufeufeu Patching System)" ]
  ++ map renderField (dpsMeta p)
  ++ [ "records:     " ++ show (length (dpsRecords p))
     , "  copy:      " ++ show nCopy
     , "  enclosed:  " ++ show nEnclosed
     ]
  where
    nCopy = length [() | DPSRecord CopyFromROM _ _ <- dpsRecords p]
    nEnclosed = length [() | DPSRecord EnclosedData _ _ <- dpsRecords p]

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- Encodes changed regions as EnclosedData records and unchanged regions
-- as CopyFromROM records.
createDPS :: ByteString -> ByteString -> String -> String -> String -> DPSStability -> ByteString
createDPS old new name author version stability = BL.toStrict $ toLazyByteString $
    padField 64 name                    -- name
    <> padField 64 author               -- author
    <> padField 64 version              -- version
    <> word8 (fromDPSStability stability)  -- flag
    <> word8 1                          -- DPS version
    <> putWord32LE (fromIntegral (BS.length old) :: Word32)  -- orig size
    <> foldMap encodeRec (dpsRecordsFromDiff old new)
  where
    padField n s =
      let bs = BS8.pack (take n s)
      in byteString bs <> byteString (BS.replicate (n - BS.length bs) 0)

dpsRecordsFromDiff :: ByteString -> ByteString -> [(Word8, Int, ByteString)]
dpsRecordsFromDiff old new = go 0 (diffHunks old new)
  where
    go _ [] = []
    go pos ((off, dat) : rest)
      | off > pos = (0, pos, encCopy pos (off - pos))    -- CopyFromROM gap
                    : (1, off, dat)                        -- EnclosedData
                    : go (off + BS.length dat) rest
      | otherwise = (1, off, dat) : go (off + BS.length dat) rest
    encCopy srcOff len = BL.toStrict $ toLazyByteString $
      putWord32LE (fromIntegral srcOff :: Word32)
      <> putWord32LE (fromIntegral len :: Word32)

encodeRec :: (Word8, Int, ByteString) -> Builder
encodeRec (0, outOff, copyDat) =  -- CopyFromROM: mode + outOff + srcOff + len (pre-encoded in copyDat)
    word8 0
    <> putWord32LE (fromIntegral outOff :: Word32)
    <> byteString copyDat
encodeRec (_, outOff, dat) =      -- EnclosedData: mode + outOff + len + data
    word8 1
    <> putWord32LE (fromIntegral outOff :: Word32)
    <> putWord32LE (fromIntegral (BS.length dat) :: Word32)
    <> byteString dat
