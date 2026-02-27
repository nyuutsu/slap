{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.IPS
  ( IPSVariant(..)
  , IPSRecord(..)
  , IPSPatch(..)
  , parseIPS
  , applyIPS
  , applyIPSMemory
  , encodeIPS
  , encodeIPS32
  , encodeEBP
  , encodeEBPRaw
  , avoidSentinel
  , optimalIPSRecords
  , ipsMeta
  , ipsInfo
  , jsonPairs
  , jsonFieldCI
  ) where

-- Canonical reference: https://zerosoft.zophar.net/ips.php (Z.e.r.o, ZeroSoft, 1998-2002)
-- No formal spec exists.

import Patch.Binary (getWord24BE, getWord32BE, putWord16BE, copyBSRange)
import Patch.Get (Get, runGet, getByte, getBytes, skip, getPosition, getInput,
                  remaining)
import qualified Patch.Get as G

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Builder
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as BL
import Data.Char (toLower)
import Data.Int (Int64)
import Patch.Format (padHex, renderField)
import Data.Bits (shiftR, (.&.))
import Data.List (sort, sortBy)
import Data.Ord (comparing)
import Data.Word (Word8, Word32, Word64)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Control.Monad.ST (ST, runST)
import Data.Array (Array, listArray, (!))
import Data.Array.MArray (newArray, readArray, writeArray)
import Data.Array.ST (STUArray)
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
              when (rleCount == 0) $
                fail ("IPS: RLE record with count 0 at offset 0x"
                      ++ showHex (fromIntegral off :: Word64) "")
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
          if BS.index rest 0 == 0x7B  -- '{' → EBP JSON metadata (no truncation)
            then pure (IPSPatch variant (reverse acc) Nothing (Just rest) clean)
            else
              -- Try truncation marker, then check for trailing EBP JSON
              let trunc = if avail >= offWidth
                          then Just (fromIntegral (if offWidth == 3
                                 then getWord24BE pos input
                                 else getWord32BE pos input))
                          else Nothing
                  jsonOff = if avail >= offWidth then offWidth else avail
                  rest' = BS.drop jsonOff rest
                  ebpMeta = if not (BS.null rest') && BS.index rest' 0 == 0x7B
                            then Just rest'
                            else Nothing
              in pure (IPSPatch variant (reverse acc) trunc ebpMeta clean)
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
applyRecords h recs = do
  mapM_ applyOne recs
  pure (length recs)
  where
    applyOne (IPSRecord off dat) = do
      hSeek h AbsoluteSeek (fromIntegral off)
      BS.hPut h dat
    applyOne (IPSRecordRLE off count val) = do
      hSeek h AbsoluteSeek (fromIntegral off)
      BS.hPut h (BS.replicate count val)

-- | Apply an IPS patch in memory. Supports truncation (ipsTruncate) and
-- RLE records — both are optional IPS features that many patchers omit.
applyIPSMemory :: IPSPatch -> ByteString -> ByteString
applyIPSMemory patch source = unsafeCreate outLen $ \ptr -> do
    copyBSRange ptr 0 source 0 (min srcLen outLen)
    when (outLen > srcLen) $
      fillBytes (ptr `plusPtr` srcLen) (0 :: Word8) (outLen - srcLen)
    forM_ (ipsRecords patch) $ \case
      IPSRecord off dat ->
        copyBSRange ptr (fromIntegral off) dat 0 (BS.length dat)
      IPSRecordRLE off count val ->
        fillBytes (ptr `plusPtr` fromIntegral off) val count
  where
    srcLen = BS.length source
    recEnd (IPSRecord off dat)       = fromIntegral off + BS.length dat
    recEnd (IPSRecordRLE off cnt _)  = fromIntegral off + cnt
    maxRecEnd = foldl' max srcLen (map recEnd (ipsRecords patch))
    outLen = case ipsTruncate patch of
      Just sz -> fromIntegral sz
      Nothing -> maxRecEnd

ipsMeta :: IPSPatch -> [(String, String)]
ipsMeta p = concat
  [ case ipsTruncate p of
      Nothing -> []
      Just sz -> [("truncate", show sz ++ " bytes")]
  , ebpFields
  ]
  where
    ebpFields = case ipsEBPMeta p of
      Nothing -> []
      Just meta ->
        let pairs = jsonPairs meta
            known = ["patcher", "title", "author", "description"]
            knownFields = [ (k, v) | k <- known
                          , Just v <- [jsonFieldCI pairs k]
                          , not (null v) ]
            unknownFields = sortBy (comparing fst)
                          [ (k, v) | (k, v) <- pairs
                          , map toLower k `notElem` known
                          , not (null v) ]
        in knownFields ++ unknownFields

ipsInfo :: IPSPatch -> String
ipsInfo p = unlines $ filter (not . null) $
  [ "format:      " ++ case ipsVariant p of
      StandardIPS -> case ipsEBPMeta p of
        Nothing -> "IPS"
        Just _  -> "IPS (EBP)"
      IPS32       -> "IPS32"
  ]
  ++ map renderField (ipsMeta p)
  ++ [ "records:     " ++ show (length (ipsRecords p))
     , "total bytes: " ++ show totalBytes
     , rangeStr
     ]
  where
    totalBytes = sum (map recSize (ipsRecords p))
    recSize (IPSRecord _ d)       = BS.length d
    recSize (IPSRecordRLE _ c _)  = c

    rangeStr
      | null (ipsRecords p) = "range:       (empty patch)"
      | otherwise =
          let lo = minimum [ recOff r | r <- ipsRecords p ]
              hi = maximum [ recOff r + fromIntegral (recSize r) | r <- ipsRecords p ]
          in "range:       0x" ++ showHex (fromIntegral lo :: Word64) ""
             ++ " - 0x" ++ showHex (fromIntegral hi :: Word64) ""

    recOff (IPSRecord o _)       = o
    recOff (IPSRecordRLE o _ _)  = o

-- | Extract all string key-value pairs from a flat JSON object.
jsonPairs :: ByteString -> [(String, String)]
jsonPairs = parsePairs . BS8.unpack
  where
    parsePairs s = case dropWhile (/= '{') s of
      ('{':rest) -> go rest
      _          -> []
    go s = case dropWhile (\c -> c == ' ' || c == ',' || c == '\n' || c == '\r') s of
      ('}':_)    -> []
      ('"':rest) -> case takeQuoted rest of
        (key, afterKey) -> case dropWhile (\c -> c == ' ' || c == ':') afterKey of
          ('"':valRest) -> case takeQuoted valRest of
            (val, afterVal) -> (key, val) : go afterVal
          other -> go other   -- non-string value, skip
      _ -> []
    takeQuoted = scanQuoted []
      where
        scanQuoted acc ('"' : rest)         = (reverse acc, rest)
        scanQuoted acc ('\\' : '"' : rest)  = scanQuoted ('"' : acc) rest
        scanQuoted acc ('\\' : '\\' : rest) = scanQuoted ('\\' : acc) rest
        scanQuoted acc ('\\' : c : rest)    = scanQuoted (c : acc) rest
        scanQuoted acc (c : rest)           = scanQuoted (c : acc) rest
        scanQuoted acc []                   = (reverse acc, [])

-- | Case-insensitive key lookup in extracted JSON pairs.
jsonFieldCI :: [(String, String)] -> String -> Maybe String
jsonFieldCI pairs key =
  let lk = map toLower key
  in lookup lk [(map toLower k, v) | (k, v) <- pairs]

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

allSame :: ByteString -> Bool
allSame bs
  | BS.null bs = True
  | otherwise  = BS.all (== BS.index bs 0) bs

-- | Shift any record that starts exactly at a sentinel offset back by one byte,
-- prepending the source byte at (off-1) so the encoder never emits the sentinel
-- as a record offset.  No-op when the source is too short for the lookup.
avoidSentinel :: Int -> ByteString -> [(Int, ByteString)] -> [(Int, ByteString)]
avoidSentinel sentinel src = map fix
  where
    fix (off, dat)
      | off == sentinel, off > 0, off - 1 < BS.length src =
          (off - 1, BS.cons (BS.index src (off - 1)) dat)
      | otherwise = (off, dat)

----------------------------------------------------------------------------
-- Encode from pre-split records (used by direct conversion)
----------------------------------------------------------------------------

-- | Encode pre-split records as an IPS patch. Records must have offsets
-- ≤ 0xFFFFFF and data ≤ 65535 bytes each.
encodeIPS :: ByteString -> [(Int, ByteString)] -> Maybe Int64 -> ByteString
encodeIPS src recs trunc = BL.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) (avoidSentinel 0x454F46 src recs)
  <> byteString "EOF"
  <> maybe mempty (truncOffset 3) trunc

-- | Encode pre-split records as an IPS32 patch. Records must have data
-- ≤ 65535 bytes each.
encodeIPS32 :: ByteString -> [(Int, ByteString)] -> Maybe Int64 -> ByteString
encodeIPS32 src recs trunc = BL.toStrict $ toLazyByteString $
  byteString "IPS32"
  <> foldMap (encodeIPSRecord 4) (avoidSentinel 0x45454F46 src recs)
  <> byteString "EEOF"
  <> maybe mempty (truncOffset 4) trunc

-- | Encode pre-split records as an EBP patch (IPS + JSON metadata).
-- Truncation marker (if any) goes between EOF and JSON.
encodeEBP :: ByteString -> [(Int, ByteString)] -> Maybe Int64 -> String -> String -> String -> ByteString
encodeEBP src recs trunc title author desc = BL.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) (avoidSentinel 0x454F46 src recs)
  <> byteString "EOF"
  <> maybe mempty (truncOffset 3) trunc
  <> byteString (ebpJson title author desc)

-- | Encode pre-split records as an EBP patch with raw JSON metadata blob.
-- Used by direct conversion to preserve source EBP metadata as-is.
encodeEBPRaw :: ByteString -> [(Int, ByteString)] -> Maybe Int64 -> ByteString -> ByteString
encodeEBPRaw src recs trunc meta = BL.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) (avoidSentinel 0x454F46 src recs)
  <> byteString "EOF"
  <> maybe mempty (truncOffset 3) trunc
  <> byteString meta

truncOffset :: Int -> Int64 -> Builder
truncOffset w off = encodeOffset w (fromIntegral off)

ebpJson :: String -> String -> String -> ByteString
ebpJson t a d = BS8.pack $
  "{\"patcher\":\"slap\",\"title\":\"" ++ escapeJson t
  ++ "\",\"author\":\"" ++ escapeJson a
  ++ "\",\"description\":\"" ++ escapeJson d ++ "\"}"
  where
    escapeJson [] = []
    escapeJson ('"':cs)  = '\\' : '"'  : escapeJson cs
    escapeJson ('\\':cs) = '\\' : '\\' : escapeJson cs
    escapeJson (c:cs)
      | c < ' '   = "\\u00" ++ padHex 2 (fromIntegral (fromEnum c)) ++ escapeJson cs
      | otherwise  = c : escapeJson cs

----------------------------------------------------------------------------
-- Optimal IPS record generation via DP
----------------------------------------------------------------------------

-- | Compute optimal IPS record set via DP.
-- Considers RLE extraction and gap merging with format-aware thresholds.
-- offWidth is 3 for IPS/EBP, 4 for IPS32.
optimalIPSRecords :: Int -> ByteString -> ByteString -> [(Int, ByteString)]
optimalIPSRecords offWidth src tgt =
  concatMap (partitionOptimal offWidth) (mergeGaps offWidth tgt (diffRaw src tgt))

-- | Diff without gap merging — raw changed regions.
diffRaw :: ByteString -> ByteString -> [(Int, ByteString)]
diffRaw old new = go 0 ++ extension
  where
    oldLen = BS.length old
    newLen = BS.length new
    minLen = min oldLen newLen
    extension
      | newLen > oldLen = [(oldLen, BS.drop oldLen new)]
      | otherwise       = []
    go i
      | i >= minLen = []
      | BS.index old i == BS.index new i = go (i + 1)
      | otherwise =
          let end = findEnd (i + 1)
          in (i, BS.take (end - i) (BS.drop i new)) : go end
    findEnd j
      | j >= minLen = minLen
      | BS.index old j /= BS.index new j = findEnd (j + 1)
      | otherwise = j

-- | Merge hunks with gaps <= offWidth+1 (the break-even for separate records).
mergeGaps :: Int -> ByteString -> [(Int, ByteString)] -> [(Int, ByteString)]
mergeGaps _ _ [] = []
mergeGaps _ _ [x] = [x]
mergeGaps offWidth tgt ((o1,d1):(o2,d2):rest)
  | o2 - (o1 + BS.length d1) <= offWidth + 1 =
      let merged = BS.take (o2 + BS.length d2 - o1) (BS.drop o1 tgt)
      in mergeGaps offWidth tgt ((o1, merged) : rest)
  | otherwise = (o1,d1) : mergeGaps offWidth tgt ((o2,d2):rest)

-- | DP within a single block to find optimal Copy/RLE record partition.
-- Returns records with absolute offsets and data <= 65535 bytes each.
partitionOptimal :: Int -> (Int, ByteString) -> [(Int, ByteString)]
partitionOptimal offWidth (blockOff, blockData)
  | BS.null blockData = []
  | otherwise = runST go
  where
    n = BS.length blockData
    inf = n * (offWidth + 7) + 1
    runs = findByteRuns blockData
    rawPos = dedup . sort $
      [0, n] ++ concatMap (\(a, b) -> [a, b]) runs
    positions = ensureMaxGap 0xFFFF rawPos
    k = length positions
    posArr = listArray (0, k - 1) positions :: Array Int Int
    rlePreds = listArray (0, k - 1) (computeRLEPreds positions runs)
                 :: Array Int Int

    go :: forall s. ST s [(Int, ByteString)]
    go = do
      costA <- newArray (0, k - 1) inf :: ST s (STUArray s Int Int)
      predA <- newArray (0, k - 1) (-1) :: ST s (STUArray s Int Int)
      writeArray costA 0 0

      forM_ [1 .. k - 1] $ \j -> do
        let pj = posArr ! j

        -- Copy: scan backward within 65535 window
        let scanCopy best bestI i
              | i < 0 = pure (best, bestI)
              | pj - (posArr ! i) > 0xFFFF = pure (best, bestI)
              | otherwise = do
                  ci <- readArray costA i
                  let c = ci + offWidth + 2 + pj - (posArr ! i)
                  if c < best
                    then scanCopy c i (i - 1)
                    else scanCopy best bestI (i - 1)
        (copyCost, copyIdx) <- scanCopy inf (-1) (j - 1)

        -- RLE option
        let rp = rlePreds ! j
        (bestCost, bestIdx) <-
          if rp >= 0 && pj - (posArr ! rp) > 3 then do
            cr <- readArray costA rp
            let rleCost = cr + offWidth + 5
            pure $ if rleCost < copyCost
              then (rleCost, rp)
              else (copyCost, copyIdx)
          else pure (copyCost, copyIdx)

        writeArray costA j bestCost
        writeArray predA j bestIdx

      -- Backtrack from final position to extract records in order
      let extract j acc
            | j <= 0 = pure acc
            | otherwise = do
                p <- readArray predA j
                let st = posArr ! p
                    en = posArr ! j
                    dat = BS.take (en - st) (BS.drop st blockData)
                extract p ((blockOff + st, dat) : acc)

      extract (k - 1) []

-- | Find maximal same-byte runs >= 4 bytes.  Returns [(start, end)].
findByteRuns :: ByteString -> [(Int, Int)]
findByteRuns bs
  | BS.null bs = []
  | otherwise  = go 0 (BS.index bs 0) 1
  where
    n = BS.length bs
    go start byte i
      | i >= n    = [(start, n) | n - start >= 4]
      | BS.index bs i == byte = go start byte (i + 1)
      | otherwise = [(start, i) | i - start >= 4]
                    ++ go i (BS.index bs i) (i + 1)

-- | Ensure no two consecutive positions are more than maxGap apart.
ensureMaxGap :: Int -> [Int] -> [Int]
ensureMaxGap _ [] = []
ensureMaxGap _ [x] = [x]
ensureMaxGap mg (a:b:rest)
  | b - a <= mg = a : ensureMaxGap mg (b : rest)
  | otherwise   = a : ensureMaxGap mg ((a + mg) : b : rest)

-- | Remove consecutive duplicates from a sorted list.
dedup :: (Eq a) => [a] -> [a]
dedup [] = []
dedup [x] = [x]
dedup (x:y:rest)
  | x == y    = dedup (y : rest)
  | otherwise = x : dedup (y : rest)

-- | For each position, find the RLE predecessor (previous position in same
-- maximal run), or -1 if none.
computeRLEPreds :: [Int] -> [(Int, Int)] -> [Int]
computeRLEPreds positions runs =
  (-1) : [ if sameRun prev cur then j - 1 else (-1)
         | (j, (prev, cur)) <- zip [1..] (zip positions (drop 1 positions)) ]
  where
    sameRun p q = any (\(rs, re) -> rs <= p && q <= re) runs

