{-# LANGUAGE OverloadedStrings #-}

module Slap.IPS.Create
  ( encodeIPSRecord
  , encodeOffset
  , allSame
  , avoidSentinel
  , encodeIPS
  , encodeIPS32
  , encodeEBP
  , encodeEBPRaw
  , encodeTruncation
  , ebpJson
  , optimalIPSRecords
  , diffRaw
  , mergeGaps
  , partitionOptimal
  , findByteRuns
  , ensureMaxGap
  , splitHunks
  ) where

import Slap.Binary (putWord16BE)
import Slap.IPS.Types (ipsMaxRecordData)
import Slap.Measure (Offset(..), FileSize(..), Length(..), Delta(..), Hunk(..), EncodedHunk(..),
                     offsetToInt, advance, displace, ipsSentinel, ips32Sentinel)
import Slap.Format (padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Bits (shiftR, (.&.))
import Data.List (sort)
import Control.Monad (forM_)
import Control.Monad.ST (ST, runST)
import Data.Array (Array, listArray, (!))
import Data.Array.MArray (newArray, readArray, writeArray)
import Data.Array.ST (STUArray)

encodeIPSRecord :: Int -> EncodedHunk -> Builder
encodeIPSRecord offsetWidth (EncodedHunk offset payload) =
  encodeOffset offsetWidth (offsetToInt offset)
  -- Check for RLE: all same byte and length >= 3
  <> if ByteString.length payload >= 3 && allSame payload
     then -- RLE record: size=0, then rle_count, rle_value
       word8 0 <> word8 0
       <> putWord16BE (fromIntegral (ByteString.length payload))
       <> word8 (ByteString.index payload 0)
     else -- Normal record: size, data
       putWord16BE (fromIntegral (ByteString.length payload))
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
avoidSentinel :: Int -> ByteString -> [EncodedHunk] -> [EncodedHunk]
avoidSentinel sentinel source = map adjustRecord
  where
    sentinelOffset = Offset (fromIntegral sentinel)
    adjustRecord (EncodedHunk hunkOffset hunkPayload)
      | hunkOffset == sentinelOffset, offsetToInt hunkOffset > 0, offsetToInt hunkOffset - 1 < ByteString.length source =
          let shiftedIndex = offsetToInt hunkOffset - 1
          in EncodedHunk (displace hunkOffset (Delta (-1))) (ByteString.cons (ByteString.index source shiftedIndex) hunkPayload)
      | otherwise = EncodedHunk hunkOffset hunkPayload

----------------------------------------------------------------------------
-- Encode from pre-split records (used by direct conversion)
----------------------------------------------------------------------------

-- | Encode pre-split records as an IPS patch. Records must have offsets
-- <= 0xFFFFFF and data <= ipsMaxRecordData bytes each.
encodeIPS :: ByteString -> [EncodedHunk] -> Maybe FileSize -> ByteString
encodeIPS source records truncation = LazyByteString.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) (avoidSentinel (fromIntegral ipsSentinel) source records)
  <> byteString "EOF"
  <> maybe mempty (encodeTruncation 3) truncation

-- | Encode pre-split records as an IPS32 patch. Records must have data
-- <= ipsMaxRecordData bytes each.
encodeIPS32 :: ByteString -> [EncodedHunk] -> Maybe FileSize -> ByteString
encodeIPS32 source records truncation = LazyByteString.toStrict $ toLazyByteString $
  byteString "IPS32"
  <> foldMap (encodeIPSRecord 4) (avoidSentinel (fromIntegral ips32Sentinel) source records)
  <> byteString "EEOF"
  <> maybe mempty (encodeTruncation 4) truncation

-- | Encode pre-split records as an EBP patch (IPS + JSON metadata).
-- Truncation marker (if any) goes between EOF and JSON.
encodeEBP :: ByteString -> [EncodedHunk] -> Maybe FileSize -> String -> String -> String -> ByteString
encodeEBP source records truncation title author description = LazyByteString.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) (avoidSentinel (fromIntegral ipsSentinel) source records)
  <> byteString "EOF"
  <> maybe mempty (encodeTruncation 3) truncation
  <> byteString (ebpJson title author description)

-- | Encode pre-split records as an EBP patch with raw JSON metadata blob.
-- Used by direct conversion to preserve source EBP metadata as-is.
encodeEBPRaw :: ByteString -> [EncodedHunk] -> Maybe FileSize -> ByteString -> ByteString
encodeEBPRaw source records truncation meta = LazyByteString.toStrict $ toLazyByteString $
  byteString "PATCH"
  <> foldMap (encodeIPSRecord 3) (avoidSentinel (fromIntegral ipsSentinel) source records)
  <> byteString "EOF"
  <> maybe mempty (encodeTruncation 3) truncation
  <> byteString meta

encodeTruncation :: Int -> FileSize -> Builder
encodeTruncation width truncSize = encodeOffset width (fromIntegral (unFileSize truncSize))

ebpJson :: String -> String -> String -> ByteString
ebpJson title author description = Text.encodeUtf8 $ Text.pack $
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
-- offsetWidth is 3 for IPS/EBP, 4 for IPS32.
optimalIPSRecords :: Int -> ByteString -> ByteString -> [EncodedHunk]
optimalIPSRecords offsetWidth source target =
  concatMap (partitionOptimal offsetWidth) (mergeGaps offsetWidth target (diffRaw source target))

-- | Diff without gap merging -- raw changed regions.
diffRaw :: ByteString -> ByteString -> [EncodedHunk]
diffRaw original modified = scanDiffs 0 ++ extension
  where
    originalLength = ByteString.length original
    modifiedLength = ByteString.length modified
    sharedLength = min originalLength modifiedLength
    extension
      | modifiedLength > originalLength = [EncodedHunk (Offset (fromIntegral originalLength)) (ByteString.drop originalLength modified)]
      | otherwise                       = []
    scanDiffs position
      | position >= sharedLength = []
      | ByteString.index original position == ByteString.index modified position = scanDiffs (position + 1)
      | otherwise =
          let diffEnd = findDiffEnd (position + 1)
          in EncodedHunk (Offset (fromIntegral position)) (ByteString.take (diffEnd - position) (ByteString.drop position modified)) : scanDiffs diffEnd
    findDiffEnd position
      | position >= sharedLength = sharedLength
      | ByteString.index original position /= ByteString.index modified position = findDiffEnd (position + 1)
      | otherwise = position

-- | Merge hunks with gaps <= offsetWidth+1 (the break-even for separate records).
mergeGaps :: Int -> ByteString -> [EncodedHunk] -> [EncodedHunk]
mergeGaps _ _ [] = []
mergeGaps _ _ [hunk] = [hunk]
mergeGaps offsetWidth target (EncodedHunk firstOffset firstData : EncodedHunk nextOffset nextData : rest)
  | offsetToInt nextOffset - (offsetToInt firstOffset + ByteString.length firstData) <= offsetWidth + 1 =
      let merged = ByteString.take (offsetToInt nextOffset + ByteString.length nextData - offsetToInt firstOffset)
                     (ByteString.drop (offsetToInt firstOffset) target)
      in mergeGaps offsetWidth target (EncodedHunk firstOffset merged : rest)
  | otherwise = EncodedHunk firstOffset firstData : mergeGaps offsetWidth target (EncodedHunk nextOffset nextData : rest)

-- | DP within a single block to find optimal Copy/RLE record partition.
-- Returns records with absolute offsets and data <= ipsMaxRecordData bytes each.
partitionOptimal :: Int -> EncodedHunk -> [EncodedHunk]
partitionOptimal offsetWidth (EncodedHunk blockOffset blockData)
  | ByteString.null blockData = []
  | otherwise = runST buildOptimal
  where
    blockLength = ByteString.length blockData
    upperBound = blockLength * (offsetWidth + 7) + 1
    runs = findByteRuns blockData
    rawPositions = deduplicate . sort $
      [0, blockLength] ++ concatMap (\(runStart, runEnd) -> [runStart, runEnd]) runs
    positions = ensureMaxGap ipsMaxRecordData rawPositions
    positionCount = length positions
    positionArray = listArray (0, positionCount - 1) positions :: Array Int Int
    rlePredecessors = listArray (0, positionCount - 1) (computeRLEPredecessors positions runs)
                       :: Array Int Int

    blockOffsetInt = offsetToInt blockOffset
    buildOptimal :: forall s. ST s [EncodedHunk]
    buildOptimal = do
      costArray <- newArray (0, positionCount - 1) upperBound :: ST s (STUArray s Int Int)
      predecessorArray <- newArray (0, positionCount - 1) (-1) :: ST s (STUArray s Int Int)
      writeArray costArray 0 0

      forM_ [1 .. positionCount - 1] $ \targetIndex -> do
        let targetPosition = positionArray ! targetIndex

        -- Copy: scan backward within ipsMaxRecordData window
        let scanCopy bestCost bestSource sourceIndex
              | sourceIndex < 0 = pure (bestCost, bestSource)
              | targetPosition - (positionArray ! sourceIndex) > ipsMaxRecordData = pure (bestCost, bestSource)
              | otherwise = do
                  sourceCost <- readArray costArray sourceIndex
                  let candidateCost = sourceCost + offsetWidth + 2 + targetPosition - (positionArray ! sourceIndex)
                  if candidateCost < bestCost
                    then scanCopy candidateCost sourceIndex (sourceIndex - 1)
                    else scanCopy bestCost bestSource (sourceIndex - 1)
        (copyCost, copySource) <- scanCopy upperBound (-1) (targetIndex - 1)

        -- RLE option
        let rlePredecessor = rlePredecessors ! targetIndex
        (bestCost, bestSource) <-
          if rlePredecessor >= 0 && targetPosition - (positionArray ! rlePredecessor) > 3 then do
            rlePredecessorCost <- readArray costArray rlePredecessor
            let rleCost = rlePredecessorCost + offsetWidth + 5
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
                extract sourceIndex (EncodedHunk (Offset (fromIntegral (blockOffsetInt + startPosition))) payload : accumulated)

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

-- | Split hunks so each payload is <= maxSize bytes.
splitHunks :: Int -> [Hunk] -> [Hunk]
splitHunks maxSize = concatMap splitOne
  where
    splitOne (Hunk hunkOffset hunkPayload)
      | ByteString.length hunkPayload <= maxSize = [Hunk hunkOffset hunkPayload]
      | otherwise =
          let (chunk, remaining) = ByteString.splitAt maxSize hunkPayload
              nextOffset = advance hunkOffset (Length maxSize)
          in Hunk hunkOffset chunk : splitOne (Hunk nextOffset remaining)

-- | Remove consecutive duplicates from a sorted list.
deduplicate :: (Eq a) => [a] -> [a]
deduplicate [] = []
deduplicate [single] = [single]
deduplicate (first:second:rest)
  | first == second = deduplicate (second : rest)
  | otherwise       = first : deduplicate (second : rest)

-- | For each position, find the RLE predecessor (previous position in same
-- maximal run), or -1 if none.
computeRLEPredecessors :: [Int] -> [(Int, Int)] -> [Int]
computeRLEPredecessors positions runs =
  (-1) : [ if sameRun previous current then positionIndex - 1 else (-1)
         | (positionIndex, (previous, current)) <- zip [1..] (zip positions (drop 1 positions)) ]
  where
    sameRun previous current = any (\(runStart, runEnd) -> runStart <= previous && current <= runEnd) runs
