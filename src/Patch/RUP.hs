{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.RUP
  ( RUPPatch(..)
  , RUPInfo(..)
  , RUPRecord(..)
  , parseRUP
  , applyRUP
  , createRUP
  , rupInfo
  ) where

import Patch.Get (Get, runGet, getByte, getBytes, skip, atEnd)
import Patch.Binary (diffHunks)
import Patch.Format (padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Bits (xor, (.&.), shiftR)
import Data.Int (Int64)
import Data.Word (Word8)
import Control.Monad (when)
import System.IO

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data RUPPatch = RUPPatch
  { rupMeta      :: RUPInfo
  , rupRecords   :: [RUPRecord]
  , rupOverflow  :: Maybe ByteString  -- data to append (for size changes)
  , rupSourceMD5 :: Maybe ByteString  -- 16 bytes
  , rupTargetMD5 :: Maybe ByteString  -- 16 bytes
  , rupSourceSz  :: Int64
  , rupTargetSz  :: Int64
  } deriving (Show)

data RUPInfo = RUPInfo
  { rupAuthor      :: Maybe ByteString
  , rupVersion     :: Maybe ByteString
  , rupTitle       :: Maybe ByteString
  , rupGenre       :: Maybe ByteString
  , rupLanguage    :: Maybe ByteString
  , rupDate        :: Maybe ByteString
  , rupWebsite     :: Maybe ByteString
  , rupDescription :: Maybe ByteString
  } deriving (Show)

data RUPRecord = RUPRecord
  { rupRecOffset :: Int64
  , rupRecXor    :: ByteString
  } deriving (Show)


----------------------------------------------------------------------------
-- VLV: Variable Length Value (1-byte length prefix, then N LE bytes)
----------------------------------------------------------------------------

packedInt :: Get Int64
packedInt = do
  n <- fromIntegral <$> getByte
  bytes <- getBytes n
  -- Only interpret first 8 bytes (enough for Int64); extra bytes are
  -- consumed from the stream but don't contribute to the value.
  let n' = min n 8
  pure $ foldl' (\acc i ->
    acc + fromIntegral (BS.index bytes i) * (256 ^ i)) 0 [0..n'-1]

packedBS :: Get ByteString
packedBS = do
  len <- fromIntegral <$> packedInt
  getBytes len

----------------------------------------------------------------------------
-- Fixed header (2048 bytes): NINJA2 format
----------------------------------------------------------------------------

headerSize :: Int
headerSize = 0x800  -- 2048 bytes

parseFixedHeader :: ByteString -> RUPInfo
parseFixedHeader bs = RUPInfo
  { rupAuthor      = extractField 0x008 84
  , rupVersion     = extractField 0x05C 11
  , rupTitle       = extractField 0x067 256
  , rupGenre       = extractField 0x167 48
  , rupLanguage    = extractField 0x197 48
  , rupDate        = extractField 0x1C7 8
  , rupWebsite     = extractField 0x1CF 512
  , rupDescription = extractField 0x3CF 1073
  }
  where
    extractField offset len =
      let field = BS.take len (BS.drop offset bs)
          trimmed = BS.takeWhile (/= 0) field
      in if BS.null trimmed then Nothing else Just trimmed

----------------------------------------------------------------------------
-- Command stream (starts at offset 0x800)
--   0x01: OPEN_NEW_FILE
--   0x02: XOR record
--   0x00: END
----------------------------------------------------------------------------

parseRUP :: ByteString -> Either String RUPPatch
parseRUP bs
  | BS.length bs < 7 = Left "too short for RUP header"
  | BS.take 7 bs /= "NINJA2\0" = Left "not a RUP file (bad magic)"
  | BS.length bs < headerSize = Left "truncated RUP header"
  | otherwise = runGet parseRUP' bs
  where
    parseRUP' :: Get RUPPatch
    parseRUP' = do
      hdr <- getBytes headerSize
      let meta = parseFixedHeader hdr
      p <- parseCommands (emptyPatch meta)
      pure p { rupRecords = reverse (rupRecords p) }

    emptyPatch m = RUPPatch m [] Nothing Nothing Nothing 0 0

parseCommands :: RUPPatch -> Get RUPPatch
parseCommands patch = do
  done <- atEnd
  if done then pure patch
  else do
    code <- getByte
    case code of
      0x01 -> parseFileCmd patch >>= parseCommands
      0x02 -> parseXorRecord patch >>= parseCommands
      0x00 -> pure patch  -- END marker
      _    -> pure patch  -- unknown, stop

-- | Command 0x01: OPEN_NEW_FILE
parseFileCmd :: RUPPatch -> Get RUPPatch
parseFileCmd patch = do
  _filename <- packedBS
  skip 1  -- ROM type byte
  srcSz <- packedInt
  tgtSz <- packedInt
  srcMD5 <- getBytes 16
  tgtMD5 <- getBytes 16
  overflow <- if srcSz /= tgtSz
    then do
      skip 1  -- overflow type byte
      Just <$> packedBS
    else pure Nothing
  pure patch { rupSourceMD5 = Just srcMD5
             , rupTargetMD5 = Just tgtMD5
             , rupSourceSz  = srcSz
             , rupTargetSz  = tgtSz
             , rupOverflow  = overflow
             }

-- | Command 0x02: XOR record
parseXorRecord :: RUPPatch -> Get RUPPatch
parseXorRecord patch = do
  off <- packedInt
  xorDat <- packedBS
  pure patch { rupRecords = RUPRecord off xorDat : rupRecords patch }

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyRUP :: RUPPatch -> FilePath -> IO Int
applyRUP patch target = do
  withBinaryFile target ReadWriteMode $ \h -> do
    mapM_ (applyRecord h) (rupRecords patch)
    -- Handle overflow (append data for file size changes)
    case rupOverflow patch of
      Nothing -> pure ()
      Just overflow -> do
        let appendPos = rupSourceSz patch
        hSeek h AbsoluteSeek (fromIntegral appendPos)
        BS.hPut h overflow
    -- Handle truncation (if target is smaller than source)
    when (rupTargetSz patch > 0 && rupTargetSz patch < rupSourceSz patch) $
      hSetFileSize h (fromIntegral (rupTargetSz patch))
  pure (length (rupRecords patch))

applyRecord :: Handle -> RUPRecord -> IO ()
applyRecord h (RUPRecord off xorDat) = do
  hSeek h AbsoluteSeek (fromIntegral off)
  srcBytes <- BS.hGet h (BS.length xorDat)
  let padded = if BS.length srcBytes < BS.length xorDat
               then srcBytes <> BS.replicate (BS.length xorDat - BS.length srcBytes) 0
               else srcBytes
      result = BS.packZipWith xor padded xorDat
  hSeek h AbsoluteSeek (fromIntegral off)
  BS.hPut h result

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

rupInfo :: RUPPatch -> String
rupInfo p = unlines $ filter (not . null)
  [ "format:      RUP (NINJA2)"
  , metaField "title"       (rupTitle (rupMeta p))
  , metaField "author"      (rupAuthor (rupMeta p))
  , metaField "version"     (rupVersion (rupMeta p))
  , metaField "date"        (rupDate (rupMeta p))
  , metaField "genre"       (rupGenre (rupMeta p))
  , metaField "language"    (rupLanguage (rupMeta p))
  , metaField "website"     (rupWebsite (rupMeta p))
  , metaField "description" (rupDescription (rupMeta p))
  , sizeStr
  , md5Str "source MD5" (rupSourceMD5 p)
  , md5Str "target MD5" (rupTargetMD5 p)
  , "records:     " ++ show (length (rupRecords p))
  , overflowStr
  ]
  where
    metaField _     Nothing  = ""
    metaField label (Just v) = label ++ ": " ++ padLabel label ++ show v
    padLabel s = replicate (13 - length s - 2) ' '

    sizeStr
      | rupSourceSz p == 0 && rupTargetSz p == 0 = ""
      | otherwise = "source size: " ++ show (rupSourceSz p)
                    ++ "\ntarget size: " ++ show (rupTargetSz p)

    md5Str _ Nothing = ""
    md5Str label (Just md5) =
      label ++ ":  " ++ concatMap (\b -> padHex 2 (fromIntegral b)) (BS.unpack md5)

    overflowStr = case rupOverflow p of
      Nothing -> ""
      Just d  -> "overflow:    " ++ show (BS.length d) ++ " bytes"

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a RUP/NINJA2 patch from original and modified ByteStrings.
-- XOR-based records with VLV encoding; handles size changes via overflow.
createRUP :: ByteString -> ByteString -> ByteString
createRUP old new = BL.toStrict $ toLazyByteString $
    byteString "NINJA2\0"                -- magic (7 bytes)
    <> word8 0                           -- ROM type: raw
    <> byteString (BS.replicate (headerSize - 8) 0)  -- rest of 2048-byte header
    <> word8 0x01                        -- OPEN_NEW_FILE command
    <> putVLV 0                          -- filename length (empty)
    <> word8 0                           -- ROM type byte
    <> putVLV (fromIntegral (BS.length old))   -- source size
    <> putVLV (fromIntegral (BS.length new))   -- target size
    <> byteString (BS.replicate 16 0)    -- source MD5 (unknown)
    <> byteString (BS.replicate 16 0)    -- target MD5 (unknown)
    <> overflowPart
    <> foldMap encodeXorRec xorHunks
    <> word8 0x00                        -- END command
  where
    -- XOR hunks over the shared region
    minLen = min (BS.length old) (BS.length new)
    oldTrim = BS.take minLen old
    newTrim = BS.take minLen new
    -- diffHunks finds changed regions; we then XOR old and new at those positions
    xorHunks = map toXor (diffHunks oldTrim newTrim)
    toXor (off, newDat) =
      let oldDat = BS.take (BS.length newDat) (BS.drop off oldTrim)
      in (off, BS.packZipWith xor oldDat newDat)

    -- Overflow: if new is longer, emit the extra bytes
    overflowPart
      | BS.length new > BS.length old =
          let extra = BS.drop (BS.length old) new
          in word8 0  -- overflow type
             <> putVLV (fromIntegral (BS.length extra))
             <> byteString extra
      | otherwise = mempty

encodeXorRec :: (Int, ByteString) -> Builder
encodeXorRec (off, dat) =
    word8 0x02                                -- XOR command
    <> putVLV (fromIntegral off)              -- offset
    <> putVLV (fromIntegral (BS.length dat))  -- length
    <> byteString dat                         -- XOR data (from diffHunks, these are new bytes not XOR)

-- | VLV: 1-byte length prefix, then N bytes little-endian.
putVLV :: Int64 -> Builder
putVLV 0 = word8 1 <> word8 0
putVLV n =
  let bytes = vlvBytes n
  in word8 (fromIntegral (length bytes)) <> foldMap word8 bytes

vlvBytes :: Int64 -> [Word8]
vlvBytes 0 = []
vlvBytes n = fromIntegral (n .&. 0xFF) : vlvBytes (n `shiftR` 8)

