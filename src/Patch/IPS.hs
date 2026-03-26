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

import Patch.Binary (getWord24BE, getWord32BE, putWord16BE, copyByteStringRange)
import Patch.Get (Get, runGet, getByte, getBytes, skip, getPosition, getInput,
                  remaining)
import qualified Patch.Get as Get

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.ByteString.Builder
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as LazyByteString
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
parseIPS input
  | ByteString.take 5 input == "PATCH" = runGet (skip 5 >> parseRecords StandardIPS 3 0x454F46) input
  | ByteString.take 5 input == "IPS32" = runGet (skip 5 >> parseRecords IPS32 4 0x45454F46) input
  | otherwise = Left "not an IPS file (bad magic)"

parseRecords :: IPSVariant -> Int -> Word32 -> Get IPSPatch
parseRecords variant offWidth eofMarker = parseLoop []
  where
    -- Peek at the next offWidth bytes to check for EOF marker without consuming.
    peekEOF :: Get (Maybe Bool)
    peekEOF = do
      available <- remaining
      if available < offWidth then pure Nothing
      else do
        position <- getPosition
        inputBytes <- getInput
        pure $ Just $ if offWidth == 3
               then getWord24BE position inputBytes == eofMarker
               else getWord32BE position inputBytes == eofMarker

    readOffset :: Get Int64
    readOffset
      | offWidth == 3 = fromIntegral <$> Get.word24BE
      | otherwise     = fromIntegral <$> Get.word32BE

    parseLoop accumulated = do
      eof <- peekEOF
      case eof of
        Nothing -> finish accumulated False       -- ran out of bytes, no EOF marker
        Just True -> do
          skip offWidth
          finish accumulated True                 -- proper EOF marker found
        Just False -> do
          offset <- readOffset
          size   <- fromIntegral <$> Get.word16BE :: Get Int
          if size == 0
            then do  -- RLE record
              rleCount <- fromIntegral <$> Get.word16BE
              when (rleCount == 0) $
                fail ("IPS: RLE record with count 0 at offset 0x"
                      ++ showHex (fromIntegral offset :: Word64) "")
              rleFill  <- getByte
              parseLoop (IPSRecordRLE offset rleCount rleFill : accumulated)
            else do  -- Normal record
              payload <- getBytes size
              parseLoop (IPSRecord offset payload : accumulated)

    finish accumulated clean = do
      available <- remaining
      if available > 0
        then do
          position <- getPosition
          inputBytes <- getInput
          let trailing = ByteString.drop position inputBytes
          if ByteString.index trailing 0 == 0x7B  -- '{' → EBP JSON metadata (no truncation)
            then pure (IPSPatch variant (reverse accumulated) Nothing (Just trailing) clean)
            else
              -- Try truncation marker, then check for trailing EBP JSON
              let truncation = if available >= offWidth
                          then Just (fromIntegral (if offWidth == 3
                                 then getWord24BE position inputBytes
                                 else getWord32BE position inputBytes))
                          else Nothing
                  jsonStart = if available >= offWidth then offWidth else available
                  afterTruncation = ByteString.drop jsonStart trailing
                  ebpMeta = if not (ByteString.null afterTruncation) && ByteString.index afterTruncation 0 == 0x7B
                            then Just afterTruncation
                            else Nothing
              in pure (IPSPatch variant (reverse accumulated) truncation ebpMeta clean)
        else pure (IPSPatch variant (reverse accumulated) Nothing Nothing clean)

-- | Apply an IPS patch to a target file (seek-and-write).
applyIPS :: IPSPatch -> FilePath -> IO Int
applyIPS patch target = withBinaryFile target ReadWriteMode $ \handle -> do
  written <- applyRecords handle (ipsRecords patch)
  case ipsTruncate patch of
    Just truncSize -> hSetFileSize handle (fromIntegral truncSize)
    Nothing        -> pure ()
  pure written

applyRecords :: Handle -> [IPSRecord] -> IO Int
applyRecords handle records = do
  mapM_ applyOne records
  pure (length records)
  where
    applyOne (IPSRecord offset payload) = do
      hSeek handle AbsoluteSeek (fromIntegral offset)
      ByteString.hPut handle payload
    applyOne (IPSRecordRLE offset count fillValue) = do
      hSeek handle AbsoluteSeek (fromIntegral offset)
      ByteString.hPut handle (ByteString.replicate count fillValue)

-- | Apply an IPS patch in memory. Supports truncation (ipsTruncate) and
-- RLE records — both are optional IPS features that many patchers omit.
applyIPSMemory :: IPSPatch -> ByteString -> ByteString
applyIPSMemory patch source = unsafeCreate outputLength $ \outputPointer -> do
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputLength)
    when (outputLength > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
    forM_ (ipsRecords patch) $ \case
      IPSRecord offset payload ->
        copyByteStringRange outputPointer (fromIntegral offset) payload 0 (ByteString.length payload)
      IPSRecordRLE offset count fillValue ->
        fillBytes (outputPointer `plusPtr` fromIntegral offset) fillValue count
  where
    sourceLength = ByteString.length source
    recordEnd (IPSRecord offset payload)          = fromIntegral offset + ByteString.length payload
    recordEnd (IPSRecordRLE offset count _)       = fromIntegral offset + count
    maxRecordEnd = foldl' max sourceLength (map recordEnd (ipsRecords patch))
    outputLength = case ipsTruncate patch of
      Just truncSize -> fromIntegral truncSize
      Nothing        -> maxRecordEnd

ipsMeta :: IPSPatch -> [(String, String)]
ipsMeta patch = concat
  [ case ipsTruncate patch of
      Nothing        -> []
      Just truncSize -> [("truncate", show truncSize ++ " bytes")]
  , ebpFields
  ]
  where
    ebpFields = case ipsEBPMeta patch of
      Nothing   -> []
      Just meta ->
        let pairs = jsonPairs meta
            known = ["patcher", "title", "author", "description"]
            knownFields = [ (key, value) | key <- known
                          , Just value <- [jsonFieldCI pairs key]
                          , not (null value) ]
            unknownFields = sortBy (comparing fst)
                          [ (key, value) | (key, value) <- pairs
                          , map toLower key `notElem` known
                          , not (null value) ]
        in knownFields ++ unknownFields

ipsInfo :: IPSPatch -> String
ipsInfo patch = unlines $ filter (not . null) $
  [ "format:      " ++ case ipsVariant patch of
      StandardIPS -> case ipsEBPMeta patch of
        Nothing -> "IPS"
        Just _  -> "IPS (EBP)"
      IPS32       -> "IPS32"
  ]
  ++ map renderField (ipsMeta patch)
  ++ [ "records:     " ++ show (length (ipsRecords patch))
     , "total bytes: " ++ show totalBytes
     , rangeString
     ]
  where
    totalBytes = sum (map recordSize (ipsRecords patch))
    recordSize (IPSRecord _ payload)          = ByteString.length payload
    recordSize (IPSRecordRLE _ count _)       = count

    rangeString
      | null (ipsRecords patch) = "range:       (empty patch)"
      | otherwise =
          let lowest  = minimum [ recordOffset record | record <- ipsRecords patch ]
              highest = maximum [ recordOffset record + fromIntegral (recordSize record)
                                | record <- ipsRecords patch ]
          in "range:       0x" ++ showHex (fromIntegral lowest :: Word64) ""
             ++ " - 0x" ++ showHex (fromIntegral highest :: Word64) ""

    recordOffset (IPSRecord offset _)       = offset
    recordOffset (IPSRecordRLE offset _ _)  = offset

-- | Extract all string key-value pairs from a flat JSON object.
jsonPairs :: ByteString -> [(String, String)]
jsonPairs = extractPairs . ByteString8.unpack
  where
    extractPairs text = case dropWhile (/= '{') text of
      ('{':rest) -> scanEntries rest
      _          -> []
    scanEntries text = case dropWhile (\char -> char == ' ' || char == ',' || char == '\n' || char == '\r') text of
      ('}':_)    -> []
      ('"':rest) -> case takeQuoted rest of
        (key, afterKey) -> case dropWhile (\char -> char == ' ' || char == ':') afterKey of
          ('"':valueRest) -> case takeQuoted valueRest of
            (value, afterValue) -> (key, value) : scanEntries afterValue
          other -> scanEntries other   -- non-string value, skip
      _ -> []
    takeQuoted = scanQuoted []
      where
        scanQuoted accumulated ('"' : rest)         = (reverse accumulated, rest)
        scanQuoted accumulated ('\\' : '"' : rest)  = scanQuoted ('"' : accumulated) rest
        scanQuoted accumulated ('\\' : '\\' : rest) = scanQuoted ('\\' : accumulated) rest
        scanQuoted accumulated ('\\' : char : rest) = scanQuoted (char : accumulated) rest
        scanQuoted accumulated (char : rest)        = scanQuoted (char : accumulated) rest
        scanQuoted accumulated []                   = (reverse accumulated, [])

-- | Case-insensitive key lookup in extracted JSON pairs.
jsonFieldCI :: [(String, String)] -> String -> Maybe String
jsonFieldCI pairs key =
  let lowerKey = map toLower key
  in lookup lowerKey [(map toLower entryKey, value) | (entryKey, value) <- pairs]

encodeIPSRecord :: Int -> (Int, ByteString) -> Builder
encodeIPSRecord offWidth (offset, payload) =
  encodeOffset offWidth offset
  -- Check for RLE: all same byte and length >= 3
  <> if ByteString.length payload >= 3 && allSame payload
     then -- RLE record: size=0, then rle_count, rle_value
       word8 0 <> word8 0
       <> putWord16BE (ByteString.length payload)
       <> word8 (ByteString.index payload 0)
     else -- Normal record: size, data
       putWord16BE (ByteString.length payload)
       <> byteString payload

-- | Encode an offset as big-endian bytes (3 for IPS, 4 for IPS32).
encodeOffset :: Int -> Int -> Builder
encodeOffset 3 offset =
  word8 (fromIntegral (offset `shiftR` 16))
  <> word8 (fromIntegral ((offset `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (offset .&. 0xFF))
encodeOffset _ offset =
  word8 (fromIntegral (offset `shiftR` 24))
  <> word8 (fromIntegral ((offset `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((offset `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (offset .&. 0xFF))

allSame :: ByteString -> Bool
allSame input
  | ByteString.null input = True
  | otherwise     = ByteString.all (== ByteString.index input 0) input

-- | Shift any record that starts exactly at a sentinel offset back by one byte,
-- prepending the source byte at (off-1) so the encoder never emits the sentinel
-- as a record offset.  No-op when the source is too short for the lookup.
avoidSentinel :: Int -> ByteString -> [(Int, ByteString)] -> [(Int, ByteString)]
avoidSentinel sentinel source = map fix
  where
    fix (offset, payload)
      | offset == sentinel, offset > 0, offset - 1 < ByteString.length source =
          (offset - 1, ByteString.cons (ByteString.index source (offset - 1)) payload)
      | otherwise = (offset, payload)

----------------------------------------------------------------------------
-- Encode from pre-split records (used by direct conversion)
----------------------------------------------------------------------------

-- | Encode pre-split records as an IPS patch. Records must have offsets
-- ≤ 0xFFFFFF and data ≤ 65535 bytes each.
encodeIPS :: ByteString -> [(Int, ByteString)] -> Maybe Int64 -> ByteString
encodeIPS source records truncation = LazyByteString.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) (avoidSentinel 0x454F46 source records)
  <> byteString "EOF"
  <> maybe mempty (truncationOffset 3) truncation

-- | Encode pre-split records as an IPS32 patch. Records must have data
-- ≤ 65535 bytes each.
encodeIPS32 :: ByteString -> [(Int, ByteString)] -> Maybe Int64 -> ByteString
encodeIPS32 source records truncation = LazyByteString.toStrict $ toLazyByteString $
  byteString "IPS32"
  <> foldMap (encodeIPSRecord 4) (avoidSentinel 0x45454F46 source records)
  <> byteString "EEOF"
  <> maybe mempty (truncationOffset 4) truncation

-- | Encode pre-split records as an EBP patch (IPS + JSON metadata).
-- Truncation marker (if any) goes between EOF and JSON.
encodeEBP :: ByteString -> [(Int, ByteString)] -> Maybe Int64 -> String -> String -> String -> ByteString
encodeEBP source records truncation title author description = LazyByteString.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) (avoidSentinel 0x454F46 source records)
  <> byteString "EOF"
  <> maybe mempty (truncationOffset 3) truncation
  <> byteString (ebpJson title author description)

-- | Encode pre-split records as an EBP patch with raw JSON metadata blob.
-- Used by direct conversion to preserve source EBP metadata as-is.
encodeEBPRaw :: ByteString -> [(Int, ByteString)] -> Maybe Int64 -> ByteString -> ByteString
encodeEBPRaw source records truncation meta = LazyByteString.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) (avoidSentinel 0x454F46 source records)
  <> byteString "EOF"
  <> maybe mempty (truncationOffset 3) truncation
  <> byteString meta

truncationOffset :: Int -> Int64 -> Builder
truncationOffset width offset = encodeOffset width (fromIntegral offset)

ebpJson :: String -> String -> String -> ByteString
ebpJson title author description = ByteString8.pack $
  "{\"patcher\":\"slap\",\"title\":\"" ++ escapeJson title
  ++ "\",\"author\":\"" ++ escapeJson author
  ++ "\",\"description\":\"" ++ escapeJson description ++ "\"}"
  where
    escapeJson [] = []
    escapeJson ('"':rest)  = '\\' : '"'  : escapeJson rest
    escapeJson ('\\':rest) = '\\' : '\\' : escapeJson rest
    escapeJson (char:rest)
      | char < ' ' = "\\u00" ++ padHex 2 (fromIntegral (fromEnum char)) ++ escapeJson rest
      | otherwise  = char : escapeJson rest

----------------------------------------------------------------------------
-- Optimal IPS record generation via DP
----------------------------------------------------------------------------

-- | Compute optimal IPS record set via DP.
-- Considers RLE extraction and gap merging with format-aware thresholds.
-- offWidth is 3 for IPS/EBP, 4 for IPS32.
optimalIPSRecords :: Int -> ByteString -> ByteString -> [(Int, ByteString)]
optimalIPSRecords offWidth source target =
  concatMap (partitionOptimal offWidth) (mergeGaps offWidth target (diffRaw source target))

-- | Diff without gap merging — raw changed regions.
diffRaw :: ByteString -> ByteString -> [(Int, ByteString)]
diffRaw original modified = scanDiffs 0 ++ extension
  where
    originalLength = ByteString.length original
    modifiedLength = ByteString.length modified
    sharedLength = min originalLength modifiedLength
    extension
      | modifiedLength > originalLength = [(originalLength, ByteString.drop originalLength modified)]
      | otherwise                       = []
    scanDiffs position
      | position >= sharedLength = []
      | ByteString.index original position == ByteString.index modified position = scanDiffs (position + 1)
      | otherwise =
          let diffEnd = findDiffEnd (position + 1)
          in (position, ByteString.take (diffEnd - position) (ByteString.drop position modified)) : scanDiffs diffEnd
    findDiffEnd position
      | position >= sharedLength = sharedLength
      | ByteString.index original position /= ByteString.index modified position = findDiffEnd (position + 1)
      | otherwise = position

-- | Merge hunks with gaps <= offWidth+1 (the break-even for separate records).
mergeGaps :: Int -> ByteString -> [(Int, ByteString)] -> [(Int, ByteString)]
mergeGaps _ _ [] = []
mergeGaps _ _ [hunk] = [hunk]
mergeGaps offWidth target ((firstOffset, firstData):(nextOffset, nextData):rest)
  | nextOffset - (firstOffset + ByteString.length firstData) <= offWidth + 1 =
      let merged = ByteString.take (nextOffset + ByteString.length nextData - firstOffset) (ByteString.drop firstOffset target)
      in mergeGaps offWidth target ((firstOffset, merged) : rest)
  | otherwise = (firstOffset, firstData) : mergeGaps offWidth target ((nextOffset, nextData) : rest)

-- | DP within a single block to find optimal Copy/RLE record partition.
-- Returns records with absolute offsets and data <= 65535 bytes each.
partitionOptimal :: Int -> (Int, ByteString) -> [(Int, ByteString)]
partitionOptimal offWidth (blockOffset, blockData)
  | ByteString.null blockData = []
  | otherwise = runST buildOptimal
  where
    blockLength = ByteString.length blockData
    upperBound = blockLength * (offWidth + 7) + 1
    runs = findByteRuns blockData
    rawPositions = dedup . sort $
      [0, blockLength] ++ concatMap (\(runStart, runEnd) -> [runStart, runEnd]) runs
    positions = ensureMaxGap 0xFFFF rawPositions
    positionCount = length positions
    positionArray = listArray (0, positionCount - 1) positions :: Array Int Int
    rlePredecessors = listArray (0, positionCount - 1) (computeRLEPredecessors positions runs)
                       :: Array Int Int

    buildOptimal :: forall s. ST s [(Int, ByteString)]
    buildOptimal = do
      costArray <- newArray (0, positionCount - 1) upperBound :: ST s (STUArray s Int Int)
      predecessorArray <- newArray (0, positionCount - 1) (-1) :: ST s (STUArray s Int Int)
      writeArray costArray 0 0

      forM_ [1 .. positionCount - 1] $ \targetIndex -> do
        let targetPosition = positionArray ! targetIndex

        -- Copy: scan backward within 65535 window
        let scanCopy bestCost bestSource sourceIndex
              | sourceIndex < 0 = pure (bestCost, bestSource)
              | targetPosition - (positionArray ! sourceIndex) > 0xFFFF = pure (bestCost, bestSource)
              | otherwise = do
                  sourceCost <- readArray costArray sourceIndex
                  let candidateCost = sourceCost + offWidth + 2 + targetPosition - (positionArray ! sourceIndex)
                  if candidateCost < bestCost
                    then scanCopy candidateCost sourceIndex (sourceIndex - 1)
                    else scanCopy bestCost bestSource (sourceIndex - 1)
        (copyCost, copySource) <- scanCopy upperBound (-1) (targetIndex - 1)

        -- RLE option
        let rlePredecessor = rlePredecessors ! targetIndex
        (bestCost, bestSource) <-
          if rlePredecessor >= 0 && targetPosition - (positionArray ! rlePredecessor) > 3 then do
            rlePredecessorCost <- readArray costArray rlePredecessor
            let rleCost = rlePredecessorCost + offWidth + 5
            pure $ if rleCost < copyCost
              then (rleCost, rlePredecessor)
              else (copyCost, copySource)
          else pure (copyCost, copySource)

        writeArray costArray targetIndex bestCost
        writeArray predecessorArray targetIndex bestSource

      -- Backtrack from final position to extract records in order
      let extract targetIndex accumulated
            | targetIndex <= 0 = pure accumulated
            | otherwise = do
                sourceIndex <- readArray predecessorArray targetIndex
                let startPosition = positionArray ! sourceIndex
                    endPosition   = positionArray ! targetIndex
                    payload  = ByteString.take (endPosition - startPosition) (ByteString.drop startPosition blockData)
                extract sourceIndex ((blockOffset + startPosition, payload) : accumulated)

      extract (positionCount - 1) []

-- | Find maximal same-byte runs >= 4 bytes.  Returns [(start, end)].
findByteRuns :: ByteString -> [(Int, Int)]
findByteRuns input
  | ByteString.null input = []
  | otherwise     = scanRuns 0 (ByteString.index input 0) 1
  where
    inputLength = ByteString.length input
    scanRuns runStart runByte position
      | position >= inputLength = [(runStart, inputLength) | inputLength - runStart >= 4]
      | ByteString.index input position == runByte = scanRuns runStart runByte (position + 1)
      | otherwise = [(runStart, position) | position - runStart >= 4]
                    ++ scanRuns position (ByteString.index input position) (position + 1)

-- | Ensure no two consecutive positions are more than maxGap apart.
ensureMaxGap :: Int -> [Int] -> [Int]
ensureMaxGap _ [] = []
ensureMaxGap _ [single] = [single]
ensureMaxGap maxGap (first:second:rest)
  | second - first <= maxGap = first : ensureMaxGap maxGap (second : rest)
  | otherwise                = first : ensureMaxGap maxGap ((first + maxGap) : second : rest)

-- | Remove consecutive duplicates from a sorted list.
dedup :: (Eq a) => [a] -> [a]
dedup [] = []
dedup [single] = [single]
dedup (first:second:rest)
  | first == second = dedup (second : rest)
  | otherwise       = first : dedup (second : rest)

-- | For each position, find the RLE predecessor (previous position in same
-- maximal run), or -1 if none.
computeRLEPredecessors :: [Int] -> [(Int, Int)] -> [Int]
computeRLEPredecessors positions runs =
  (-1) : [ if sameRun previous current then positionIndex - 1 else (-1)
         | (positionIndex, (previous, current)) <- zip [1..] (zip positions (drop 1 positions)) ]
  where
    sameRun previous current = any (\(runStart, runEnd) -> runStart <= previous && current <= runEnd) runs
