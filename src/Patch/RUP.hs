{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.RUP
  ( RUPPatch(..)
  , RUPInfo(..)
  , RUPRecord(..)
  , parseRUP
  , applyRUP
  , rupInfo
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Bits (xor)
import Data.Int (Int64)
import Control.Monad (when)
import Numeric (showHex)
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

getPackedInt :: Int -> ByteString -> (Int64, Int)
getPackedInt pos bs =
  let n = fromIntegral (BS.index bs pos) :: Int
      val = foldl (\acc i ->
        acc + fromIntegral (BS.index bs (pos + 1 + i)) * (256 ^ i)) 0 [0..n-1]
  in (val, 1 + n)

getPackedBS :: Int -> ByteString -> (ByteString, Int)
getPackedBS pos bs =
  let (len, n) = getPackedInt pos bs
      dat = BS.take (fromIntegral len) (BS.drop (pos + n) bs)
  in (dat, n + fromIntegral len)

----------------------------------------------------------------------------
-- Fixed header (2048 bytes): NINJA2 format
--   0x000-0x006: "NINJA2\0"
--   0x007:       text encoding
--   0x008-0x05B: author (84 bytes)
--   0x05C-0x066: version (11 bytes)
--   0x067-0x166: title (256 bytes)
--   0x167-0x196: genre (48 bytes)
--   0x197-0x1C6: language (48 bytes)
--   0x1C7-0x1CE: date (8 bytes)
--   0x1CF-0x3CE: web (512 bytes)
--   0x3CF-0x7FF: description (1073 bytes)
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
  | otherwise =
      let meta = parseFixedHeader bs
          p = parseCommands headerSize bs (emptyPatch meta)
      in Right p { rupRecords = reverse (rupRecords p) }
  where
    emptyPatch m = RUPPatch m [] Nothing Nothing Nothing 0 0

parseCommands :: Int -> ByteString -> RUPPatch -> RUPPatch
parseCommands pos bs patch
  | pos >= BS.length bs = patch
  | otherwise =
      let code = BS.index bs pos
      in case code of
        0x01 -> parseFileCmd (pos + 1) bs patch
        0x02 -> parseXorRecord (pos + 1) bs patch
        0x00 -> patch  -- END marker
        _    -> patch  -- unknown, stop

-- | Command 0x01: OPEN_NEW_FILE
--   VLV filename, 1 byte ROM type, VLV srcSize, VLV tgtSize,
--   16 bytes srcMD5, 16 bytes tgtMD5,
--   optional overflow if srcSize != tgtSize
parseFileCmd :: Int -> ByteString -> RUPPatch -> RUPPatch
parseFileCmd pos bs patch
  | pos >= BS.length bs = patch
  | otherwise =
      let (_filename, n1) = getPackedBS pos bs
          -- romType = BS.index bs (pos + n1)
          p2 = pos + n1 + 1  -- skip ROM type byte
          (srcSz, n2) = getPackedInt p2 bs
          (tgtSz, n3) = getPackedInt (p2 + n2) bs
          md5Start = p2 + n2 + n3
          srcMD5 = BS.take 16 (BS.drop md5Start bs)
          tgtMD5 = BS.take 16 (BS.drop (md5Start + 16) bs)
          afterMD5 = md5Start + 32
          -- Overflow: if sizes differ, read 1-byte type + VLV data
          (nextPos, overflow)
            | srcSz /= tgtSz && afterMD5 < BS.length bs =
                let (_overflowType, n4) = (BS.index bs afterMD5, 1)
                    (dat, n5) = getPackedBS (afterMD5 + n4) bs
                in (afterMD5 + n4 + n5, Just dat)
            | otherwise = (afterMD5, Nothing)
      in parseCommands nextPos bs
           (patch { rupSourceMD5 = Just srcMD5
                  , rupTargetMD5 = Just tgtMD5
                  , rupSourceSz  = srcSz
                  , rupTargetSz  = tgtSz
                  , rupOverflow  = overflow
                  })

-- | Command 0x02: XOR record
--   VLV offset, VLV+data xorBytes
parseXorRecord :: Int -> ByteString -> RUPPatch -> RUPPatch
parseXorRecord pos bs patch =
  let (off, n1) = getPackedInt pos bs
      (xorDat, n2) = getPackedBS (pos + n1) bs
      rec = RUPRecord off xorDat
  in parseCommands (pos + n1 + n2) bs
       (patch { rupRecords = rec : rupRecords patch })

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
      label ++ ":  " ++ concatMap (\b -> padH 2 (showHex b "")) (BS.unpack md5)

    overflowStr = case rupOverflow p of
      Nothing -> ""
      Just d  -> "overflow:    " ++ show (BS.length d) ++ " bytes"

padH :: Int -> String -> String
padH n s = replicate (n - length s) '0' ++ s
