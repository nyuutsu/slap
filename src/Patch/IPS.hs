{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.IPS
  ( IPSVariant(..)
  , IPSRecord(..)
  , IPSPatch(..)
  , parseIPS
  , applyIPS
  , createIPS
  , createIPS32
  , createEBP
  , encodeIPS
  , encodeIPS32
  , encodeEBP
  , encodeEBPRaw
  , ipsInfo
  ) where

import Patch.Binary (getWord24BE, getWord32BE, putWord16BE)
import Patch.Get (Get, runGet, getByte, getBytes, skip, getPosition, getInput,
                  remaining)
import qualified Patch.Get as G

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)
import Data.Bits (shiftR, (.&.))
import Data.Word (Word8, Word32, Word64)
import Numeric (showHex)
import System.IO

data IPSVariant = StandardIPS | IPS32
  deriving (Show, Eq)

data IPSRecord
  = IPSRecord    Int64 ByteString        -- offset, data
  | IPSRecordRLE Int64 Int Word8          -- offset, count, fill value
  deriving (Show)

data IPSPatch = IPSPatch
  { ipsVariant   :: IPSVariant
  , ipsRecords   :: [IPSRecord]
  , ipsTruncate  :: Maybe Int64
  , ipsEBPMeta   :: Maybe ByteString  -- raw JSON metadata (EBP format)
  , ipsCleanEOF  :: Bool              -- True if proper EOF/EEOF marker was found
  } deriving (Show)

parseIPS :: ByteString -> Either String IPSPatch
parseIPS bs
  | BS.take 5 bs == "PATCH" = runGet (skip 5 >> parseRecords StandardIPS 3 0x454F46) bs
  | BS.take 5 bs == "IPS32" = runGet (skip 5 >> parseRecords IPS32 4 0x45454F46) bs
  | otherwise = Left "not an IPS file (bad magic)"

parseRecords :: IPSVariant -> Int -> Word32 -> Get IPSPatch
parseRecords variant offWidth eofMarker = go []
  where
    -- Peek at the next offWidth bytes to check for EOF marker without consuming.
    -- Returns: Nothing = not enough bytes (truncated), Just True = EOF found,
    -- Just False = not EOF (more records).
    peekEOF :: Get (Maybe Bool)
    peekEOF = do
      avail <- remaining
      if avail < offWidth then pure Nothing
      else do
        pos <- getPosition
        input <- getInput
        pure $ Just $ if offWidth == 3
               then getWord24BE pos input == eofMarker
               else getWord32BE pos input == eofMarker

    readOff :: Get Int64
    readOff
      | offWidth == 3 = fromIntegral <$> G.word24BE
      | otherwise     = fromIntegral <$> G.word32BE

    go acc = do
      eof <- peekEOF
      case eof of
        Nothing -> finish acc False       -- ran out of bytes, no EOF marker
        Just True -> do
          skip offWidth
          finish acc True                 -- proper EOF marker found
        Just False -> do
          off  <- readOff
          size <- fromIntegral <$> G.word16BE :: Get Int
          if size == 0
            then do  -- RLE record
              rleCount <- fromIntegral <$> G.word16BE
              rleVal   <- getByte
              go (IPSRecordRLE off rleCount rleVal : acc)
            else do  -- Normal record
              dat <- getBytes size
              go (IPSRecord off dat : acc)

    finish acc clean = do
      avail <- remaining
      if avail > 0
        then do
          pos <- getPosition
          input <- getInput
          let rest = BS.drop pos input
          if BS.index rest 0 == 0x7B  -- '{' → EBP JSON metadata
            then pure (IPSPatch variant (reverse acc) Nothing (Just rest) clean)
            else let trunc = if avail >= 3
                             then Just (fromIntegral (getWord24BE pos input))
                             else Nothing
                 in pure (IPSPatch variant (reverse acc) trunc Nothing clean)
        else pure (IPSPatch variant (reverse acc) Nothing Nothing clean)

-- | Apply an IPS patch to a target file (seek-and-write).
applyIPS :: IPSPatch -> FilePath -> IO Int
applyIPS patch target = withBinaryFile target ReadWriteMode $ \h -> do
  n <- applyRecords h (ipsRecords patch)
  case ipsTruncate patch of
    Just sz -> hSetFileSize h (fromIntegral sz)
    Nothing -> pure ()
  pure n

applyRecords :: Handle -> [IPSRecord] -> IO Int
applyRecords h = go 0
  where
    go n [] = pure n
    go n (r:rs) = do
      case r of
        IPSRecord off dat -> do
          hSeek h AbsoluteSeek (fromIntegral off)
          BS.hPut h dat
        IPSRecordRLE off count val -> do
          hSeek h AbsoluteSeek (fromIntegral off)
          BS.hPut h (BS.replicate count val)
      go (n + 1) rs

ipsInfo :: IPSPatch -> String
ipsInfo p = unlines $ filter (not . null)
  [ "format:      " ++ case ipsVariant p of
      StandardIPS -> case ipsEBPMeta p of
        Nothing -> "IPS"
        Just _  -> "IPS (EBP)"
      IPS32       -> "IPS32"
  , "records:     " ++ show (length (ipsRecords p))
  , "total bytes: " ++ show totalBytes
  , rangeStr
  , truncStr
  ] ++ ebpFields
  where
    totalBytes = sum (map recSize (ipsRecords p))
    recSize (IPSRecord _ d)       = BS.length d
    recSize (IPSRecordRLE _ c _)  = c

    rangeStr
      | null (ipsRecords p) = "range:       (empty patch)"
      | otherwise =
          let offsets = map recOff (ipsRecords p)
              lo = minimum offsets
              hi = maximum offsets + fromIntegral (recSize (last (ipsRecords p)))
          in "range:       0x" ++ showHex (fromIntegral lo :: Word64) ""
             ++ " - 0x" ++ showHex (fromIntegral hi :: Word64) ""

    recOff (IPSRecord o _)       = o
    recOff (IPSRecordRLE o _ _)  = o

    truncStr = case ipsTruncate p of
      Nothing -> ""
      Just sz -> "truncate:    " ++ show sz ++ " bytes"

    ebpFields = case ipsEBPMeta p of
      Nothing -> []
      Just meta -> filter (not . null)
        [ maybe "" (\v -> "title:       " ++ v) (jsonField meta "title")
        , maybe "" (\v -> "author:      " ++ v) (jsonField meta "author")
        , maybe "" (\v -> "description: " ++ v) (jsonField meta "description")
        ]

-- | Extract a string field from a flat JSON object.
jsonField :: ByteString -> ByteString -> Maybe String
jsonField json key =
  let needle = "\"" <> key <> "\":\""
      (_, match) = BS.breakSubstring needle json
  in if BS.null match then Nothing
     else Just $ takeQuoted $ BS8.unpack $ BS.drop (BS.length needle) match

takeQuoted :: String -> String
takeQuoted ('"' : _) = ""
takeQuoted ('\\' : c : rest) = c : takeQuoted rest
takeQuoted (c : rest) = c : takeQuoted rest
takeQuoted [] = ""

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create an IPS patch by diffing two byte strings.
-- Returns Left if the files exceed 16 MB (IPS offset limit).
createIPS :: ByteString -> ByteString -> Either String ByteString
createIPS orig modified
  | BS.length modified > 0x1000000 =
      Left "file exceeds 16 MB IPS offset limit — use IPS32 or BPS instead"
  | otherwise =
      let trunc = if BS.length modified < BS.length orig
                  then Just (fromIntegral (BS.length modified))
                  else Nothing
      in Right (encodeIPS (diffToRecords 0xFFFF orig modified) trunc)

-- | Create an IPS32 patch by diffing two byte strings.
-- Returns Left if the files exceed 4 GB (IPS32 offset limit).
createIPS32 :: ByteString -> ByteString -> Either String ByteString
createIPS32 orig modified
  | BS.length modified > 0xFFFFFFFF =
      Left "file exceeds 4 GB IPS32 offset limit — use BPS instead"
  | otherwise = Right (encodeIPS32 (diffToRecords 0xFFFF orig modified) Nothing)

encodeIPSRecord :: Int -> (Int, ByteString) -> Builder
encodeIPSRecord offWidth (off, dat) =
  encodeOffset offWidth off
  -- Check for RLE: all same byte and length >= 3
  <> if BS.length dat >= 3 && allSame dat
     then -- RLE record: size=0, then rle_count, rle_value
       word8 0 <> word8 0
       <> putWord16BE (BS.length dat)
       <> word8 (BS.index dat 0)
     else -- Normal record: size, data
       putWord16BE (BS.length dat)
       <> byteString dat

-- | Encode an offset as big-endian bytes (3 for IPS, 4 for IPS32).
encodeOffset :: Int -> Int -> Builder
encodeOffset 3 off =
  word8 (fromIntegral (off `shiftR` 16))
  <> word8 (fromIntegral ((off `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (off .&. 0xFF))
encodeOffset _ off =
  word8 (fromIntegral (off `shiftR` 24))
  <> word8 (fromIntegral ((off `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((off `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (off .&. 0xFF))

-- | Create an EBP patch (IPS + JSON metadata after EOF).
createEBP :: ByteString -> ByteString -> String -> Either String ByteString
createEBP orig modified desc
  | BS.length modified > 0x1000000 =
      Left "file exceeds 16 MB IPS offset limit — use BPS instead"
  | otherwise = Right (encodeEBP (diffToRecords 0xFFFF orig modified) desc)

allSame :: ByteString -> Bool
allSame bs
  | BS.null bs = True
  | otherwise  = BS.all (== BS.index bs 0) bs

----------------------------------------------------------------------------
-- Encode from pre-split records (used by overlay conversion in Main.hs)
----------------------------------------------------------------------------

-- | Encode pre-split records as an IPS patch. Records must have offsets
-- ≤ 0xFFFFFF and data ≤ 65535 bytes each.
encodeIPS :: [(Int, ByteString)] -> Maybe Int64 -> ByteString
encodeIPS recs trunc = BL.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) recs
  <> byteString "EOF"
  <> maybe mempty (truncOffset 3) trunc

-- | Encode pre-split records as an IPS32 patch. Records must have data
-- ≤ 65535 bytes each.
encodeIPS32 :: [(Int, ByteString)] -> Maybe Int64 -> ByteString
encodeIPS32 recs trunc = BL.toStrict $ toLazyByteString $
  byteString "IPS32"
  <> foldMap (encodeIPSRecord 4) recs
  <> byteString "EEOF"
  <> maybe mempty (truncOffset 4) trunc

-- | Encode pre-split records as an EBP patch (IPS + JSON metadata).
encodeEBP :: [(Int, ByteString)] -> String -> ByteString
encodeEBP recs desc = BL.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) recs
  <> byteString "EOF"
  <> byteString (ebpJson desc)

-- | Encode pre-split records as an EBP patch with raw JSON metadata blob.
-- Used by overlay conversion to preserve source EBP metadata as-is.
encodeEBPRaw :: [(Int, ByteString)] -> ByteString -> ByteString
encodeEBPRaw recs meta = BL.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) recs
  <> byteString "EOF"
  <> byteString meta

truncOffset :: Int -> Int64 -> Builder
truncOffset w off = encodeOffset w (fromIntegral off)

ebpJson :: String -> ByteString
ebpJson d = BS8.pack $
  "{\"title\":\"\",\"author\":\"\",\"description\":\"" ++ escapeJson d ++ "\"}"
  where
    escapeJson [] = []
    escapeJson ('"':cs)  = '\\' : '"'  : escapeJson cs
    escapeJson ('\\':cs) = '\\' : '\\' : escapeJson cs
    escapeJson (c:cs)    = c : escapeJson cs

-- | Diff two byte strings into IPS records (offset, data).
-- Merges nearby differences (gap < 6 bytes) and splits at maxRecSize.
diffToRecords :: Int -> ByteString -> ByteString -> [(Int, ByteString)]
diffToRecords maxRecSize orig modified = mergeNearby maxRecSize modified $ go 0
  where
    minLen = min (BS.length orig) (BS.length modified)

    go i
      | i >= BS.length modified = []
      | i >= minLen = extraRecords i
      | BS.index orig i /= BS.index modified i = collectHunk i
      | otherwise = go (i + 1)

    collectHunk start =
      let end = findEnd start
          dat = BS.take (end - start) (BS.drop start modified)
      in splitRecord start dat ++ go end

    findEnd i
      | i >= minLen = minLen
      | i >= BS.length modified = BS.length modified
      | BS.index orig i /= BS.index modified i = findEnd (i + 1)
      | otherwise = i

    extraRecords i
      | i >= BS.length modified = []
      | otherwise = splitRecord i (BS.drop i modified)

    splitRecord off dat
      | BS.null dat = []
      | BS.length dat <= maxRecSize = [(off, dat)]
      | otherwise =
          let chunk = BS.take maxRecSize dat
              rest  = BS.drop maxRecSize dat
          in (off, chunk) : splitRecord (off + maxRecSize) rest

-- | Merge records that are within 6 bytes of each other.
-- Uses actual bytes from the modified file to fill gaps.
mergeNearby :: Int -> ByteString -> [(Int, ByteString)] -> [(Int, ByteString)]
mergeNearby _ _ [] = []
mergeNearby _ _ [x] = [x]
mergeNearby maxRecSize modBs ((off1, d1) : (off2, d2) : rest)
  | gap <= 5 && mergedLen <= maxRecSize =
      mergeNearby maxRecSize modBs ((off1, merged) : rest)
  | otherwise = (off1, d1) : mergeNearby maxRecSize modBs ((off2, d2) : rest)
  where
    end1 = off1 + BS.length d1
    gap  = off2 - end1
    fill = BS.take gap (BS.drop end1 modBs)
    merged = d1 <> fill <> d2
    mergedLen = BS.length merged
