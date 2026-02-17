{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.IPS
  ( IPSVariant(..)
  , IPSRecord(..)
  , IPSPatch(..)
  , parseIPS
  , applyIPS
  , createIPS
  , ipsInfo
  ) where

import Patch.Binary (getWord16BE, getWord24BE, getWord32BE)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)
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
  } deriving (Show)

-- | Parse an IPS or IPS32 patch from raw bytes.
parseIPS :: ByteString -> Either String IPSPatch
parseIPS bs
  | BS.take 5 bs == "PATCH" = parseWith StandardIPS 3 0x454F46 5 bs   -- EOF = "EOF"
  | BS.take 5 bs == "IPS32" = parseWith IPS32       4 0x45454F46 5 bs -- EEOF = "EEOF"
  | otherwise = Left "not an IPS file (bad magic)"

parseWith :: IPSVariant -> Int -> Word32 -> Int -> ByteString -> Either String IPSPatch
parseWith variant offWidth eofMarker start bs = go start []
  where
    readOff pos
      | offWidth == 3 = fromIntegral (getWord24BE pos bs)
      | otherwise     = fromIntegral (getWord32BE pos bs)

    atEOF pos
      | pos + offWidth > BS.length bs = True
      | offWidth == 3 = getWord24BE pos bs == eofMarker
      | otherwise     = getWord32BE pos bs == eofMarker

    go pos acc
      | pos >= BS.length bs = Right (finish pos acc)
      | atEOF pos           = Right (finish (pos + offWidth) acc)
      | pos + offWidth + 2 > BS.length bs = Left "truncated IPS record"
      | otherwise =
          let off  = readOff pos
              size = fromIntegral (getWord16BE (pos + offWidth) bs) :: Int
          in if size == 0
             then -- RLE record
               if pos + offWidth + 4 > BS.length bs
               then Left "truncated IPS RLE record"
               else let rleCount = fromIntegral (getWord16BE (pos + offWidth + 2) bs) :: Int
                        rleVal   = BS.index bs (pos + offWidth + 4)
                    in go (pos + offWidth + 5) (IPSRecordRLE off rleCount rleVal : acc)
             else -- Normal record
               let dat = BS.take size (BS.drop (pos + offWidth + 2) bs)
               in go (pos + offWidth + 2 + size) (IPSRecord off dat : acc)

    finish pos acc =
      let remaining = BS.drop pos bs
          len = BS.length remaining
      in if len > 0 && BS.index remaining 0 == 0x7B  -- '{' → EBP JSON metadata
         then IPSPatch variant (reverse acc) Nothing (Just remaining)
         else let trunc = if len >= 3
                          then Just (fromIntegral (getWord24BE pos bs))
                          else Nothing
              in IPSPatch variant (reverse acc) trunc Nothing

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

-- | Human-readable summary of an IPS patch.
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
      Left "file exceeds 16 MB IPS offset limit — use BPS instead"
  | otherwise = Right $ BL.toStrict $ toLazyByteString $
      byteString "PATCH"
      <> foldMap encodeIPSRecord (diffToRecords orig modified)
      <> byteString "EOF"
      <> truncMarker
  where
    truncMarker
      | BS.length modified < BS.length orig =
          -- IPS truncation: 3-byte big-endian size after EOF
          let sz = BS.length modified
          in word8 (fromIntegral (sz `div` 0x10000))
             <> word8 (fromIntegral ((sz `div` 0x100) `mod` 0x100))
             <> word8 (fromIntegral (sz `mod` 0x100))
      | otherwise = mempty

encodeIPSRecord :: (Int, ByteString) -> Builder
encodeIPSRecord (off, dat) =
  -- 3-byte big-endian offset
  word8 (fromIntegral (off `div` 0x10000))
  <> word8 (fromIntegral ((off `div` 0x100) `mod` 0x100))
  <> word8 (fromIntegral (off `mod` 0x100))
  -- Check for RLE: all same byte and length >= 3
  <> if BS.length dat >= 3 && allSame dat
     then -- RLE record: size=0, then rle_count, rle_value
       word8 0 <> word8 0
       <> putWord16BE' (BS.length dat)
       <> word8 (BS.index dat 0)
     else -- Normal record: size, data
       putWord16BE' (BS.length dat)
       <> byteString dat

allSame :: ByteString -> Bool
allSame bs
  | BS.null bs = True
  | otherwise  = BS.all (== BS.index bs 0) bs

putWord16BE' :: Int -> Builder
putWord16BE' n =
  word8 (fromIntegral ((n `div` 0x100) `mod` 0x100))
  <> word8 (fromIntegral (n `mod` 0x100))

-- | Diff two byte strings into IPS records (offset, data).
-- Merges nearby differences (gap < 6 bytes) and splits at 0xFFFF.
diffToRecords :: ByteString -> ByteString -> [(Int, ByteString)]
diffToRecords orig modified = mergeNearby modified $ go 0
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
      | BS.length dat <= 0xFFFF = [(off, dat)]
      | otherwise =
          let chunk = BS.take 0xFFFF dat
              rest  = BS.drop 0xFFFF dat
          in (off, chunk) : splitRecord (off + 0xFFFF) rest

-- | Merge records that are within 6 bytes of each other.
-- Uses actual bytes from the modified file to fill gaps.
mergeNearby :: ByteString -> [(Int, ByteString)] -> [(Int, ByteString)]
mergeNearby _ [] = []
mergeNearby _ [x] = [x]
mergeNearby modBs ((off1, d1) : (off2, d2) : rest)
  | gap <= 5 && mergedLen <= 0xFFFF =
      mergeNearby modBs ((off1, merged) : rest)
  | otherwise = (off1, d1) : mergeNearby modBs ((off2, d2) : rest)
  where
    end1 = off1 + BS.length d1
    gap  = off2 - end1
    fill = BS.take gap (BS.drop end1 modBs)
    merged = d1 <> fill <> d2
    mergedLen = BS.length merged
