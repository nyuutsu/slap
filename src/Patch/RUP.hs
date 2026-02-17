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
  , rupOverflow  :: Maybe ByteString  -- data to append (XORed with 0xFF during parse)
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

emptyInfo :: RUPInfo
emptyInfo = RUPInfo Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing

----------------------------------------------------------------------------
-- Packed integer: 1-byte length prefix, then N bytes little-endian
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
-- Parsing
----------------------------------------------------------------------------

parseRUP :: ByteString -> Either String RUPPatch
parseRUP bs
  | BS.length bs < 7 = Left "too short for RUP header"
  | BS.take 7 bs /= "NINJA2\0" = Left "not a RUP file (bad magic)"
  | otherwise =
      let p = parseCommands 7 bs emptyPatch
      in Right p { rupRecords = reverse (rupRecords p) }
  where
    emptyPatch = RUPPatch emptyInfo [] Nothing Nothing Nothing 0 0

parseCommands :: Int -> ByteString -> RUPPatch -> RUPPatch
parseCommands pos bs patch
  | pos >= BS.length bs = patch
  | otherwise =
      let code = BS.index bs pos
      in case code of
        0x49 -> parseInfoBlock (pos + 1) bs patch       -- 'I'
        0x4D -> parseMD5Block (pos + 1) bs patch         -- 'M'
        0x46 -> parseFileBlock (pos + 1) bs patch        -- 'F'
        0x41 -> parseOverflowBlock (pos + 1) bs patch    -- 'A'
        0x02 -> parseXorRecord (pos + 1) bs patch        -- XOR patch
        _    -> patch  -- unknown control code, stop

parseInfoBlock :: Int -> ByteString -> RUPPatch -> RUPPatch
parseInfoBlock pos bs patch
  | pos >= BS.length bs = patch
  | otherwise =
      let infoType = BS.index bs pos
          (val, consumed) = getPackedBS (pos + 1) bs
          meta = rupMeta patch
          meta' = case infoType of
            0x61 -> meta { rupAuthor = Just val }       -- 'a'
            0x76 -> meta { rupVersion = Just val }      -- 'v'
            0x74 -> meta { rupTitle = Just val }        -- 't'
            0x6A -> meta { rupGenre = Just val }        -- 'j'
            0x6C -> meta { rupLanguage = Just val }     -- 'l'
            0x64 -> meta { rupDate = Just val }         -- 'd'
            0x77 -> meta { rupWebsite = Just val }      -- 'w'
            0x62 -> meta { rupDescription = Just val }  -- 'b'
            _    -> meta
      in parseCommands (pos + 1 + consumed) bs (patch { rupMeta = meta' })

parseMD5Block :: Int -> ByteString -> RUPPatch -> RUPPatch
parseMD5Block pos bs patch
  | pos + 32 > BS.length bs = patch
  | otherwise =
      let srcMD5 = BS.take 16 (BS.drop pos bs)
          tgtMD5 = BS.take 16 (BS.drop (pos + 16) bs)
          (srcSz, n1) = getPackedInt (pos + 32) bs
          (tgtSz, n2) = getPackedInt (pos + 32 + n1) bs
      in parseCommands (pos + 32 + n1 + n2) bs
           (patch { rupSourceMD5 = Just srcMD5
                  , rupTargetMD5 = Just tgtMD5
                  , rupSourceSz = srcSz
                  , rupTargetSz = tgtSz
                  })

parseFileBlock :: Int -> ByteString -> RUPPatch -> RUPPatch
parseFileBlock pos bs patch =
  let (_name, consumed) = getPackedBS pos bs
  in parseCommands (pos + consumed) bs patch

parseOverflowBlock :: Int -> ByteString -> RUPPatch -> RUPPatch
parseOverflowBlock pos bs patch =
  let (dat, consumed) = getPackedBS pos bs
      -- Overflow data is XORed with 0xFF in the file
      decoded = BS.map (`xor` 0xFF) dat
  in parseCommands (pos + consumed) bs (patch { rupOverflow = Just decoded })

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
