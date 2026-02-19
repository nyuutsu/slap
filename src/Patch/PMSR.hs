{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.PMSR
  ( PMSRRecord(..)
  , PMSRPatch(..)
  , parsePMSR
  , applyPMSR
  , createPMSR
  , pmsrInfo
  ) where

import Patch.Get (Get, runGet, getBytes, skip, remaining)
import qualified Patch.Get as G

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)
import Data.Word (Word64)
import Numeric (showHex)
import System.IO

-- | A single PMSR record: offset + data to write.
data PMSRRecord = PMSRRecord
  { pmsrOffset :: Int64
  , pmsrData   :: ByteString
  } deriving (Show)

-- | A parsed PMSR patch.
data PMSRPatch = PMSRPatch
  { pmsrRecords :: [PMSRRecord]
  } deriving (Show)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

-- | Parse a PMSR patch from raw bytes.
-- Format: 4 bytes "PMSR" magic, uint32BE record count,
-- then for each record: uint32BE offset, uint32BE length, then data bytes.
-- Star Rod (Java) uses big-endian — this is the authoritative producer.
parsePMSR :: ByteString -> Either String PMSRPatch
parsePMSR bs
  | BS.length bs < 4 = Left "too short for PMSR header"
  | BS.take 4 bs /= "PMSR" = Left "not a PMSR file (bad magic)"
  | otherwise = runGet parsePMSR' bs

parsePMSR' :: Get PMSRPatch
parsePMSR' = do
  skip 4  -- magic
  count <- fromIntegral <$> G.word32BE
  recs  <- parseRecords count []
  pure (PMSRPatch recs)

parseRecords :: Int -> [PMSRRecord] -> Get [PMSRRecord]
parseRecords 0 acc = pure (reverse acc)
parseRecords n acc = do
  off <- fromIntegral <$> G.word32BE
  len <- fromIntegral <$> G.word32BE
  avail <- remaining
  if len > avail
    then fail ("PMSR record needs " ++ show len ++ " bytes but only "
               ++ show avail ++ " available")
    else do
      dat <- getBytes len
      parseRecords (n - 1) (PMSRRecord off dat : acc)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

-- | Apply a PMSR patch to a target file (seek-and-write, in place).
applyPMSR :: PMSRPatch -> FilePath -> IO Int
applyPMSR patch target = withBinaryFile target ReadWriteMode $ \h -> do
  go h 0 (pmsrRecords patch)
  where
    go _ n [] = pure n
    go h n (r:rs) = do
      hSeek h AbsoluteSeek (fromIntegral (pmsrOffset r))
      BS.hPut h (pmsrData r)
      go h (n + 1) rs

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a PMSR patch by diffing two byte strings.
createPMSR :: ByteString -> ByteString -> ByteString
createPMSR orig modified = BL.toStrict $ toLazyByteString $
    byteString "PMSR"
    <> word32BE (fromIntegral (length recs))
    <> foldMap encodeRec recs
  where
    recs = diffToRecordsPMSR orig modified

    encodeRec (off, dat) =
      word32BE (fromIntegral off)
      <> word32BE (fromIntegral (BS.length dat))
      <> byteString dat

-- | Diff two byte strings into PMSR records.
-- Merges nearby differences (gap < 6 bytes) and splits at 0xFFFFFF (16 MB chunks).
diffToRecordsPMSR :: ByteString -> ByteString -> [(Int, ByteString)]
diffToRecordsPMSR orig modified = mergeNearby modified $ go 0
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

    -- PMSR uses uint32BE for length, so 4 GB max per record; use 1 MB chunks
    splitRecord off dat
      | BS.null dat = []
      | BS.length dat <= 0x100000 = [(off, dat)]
      | otherwise =
          let chunk = BS.take 0x100000 dat
              rest  = BS.drop 0x100000 dat
          in (off, chunk) : splitRecord (off + 0x100000) rest

-- | Merge records that are within 8 bytes of each other.
-- Matches Star Rod's coalescing threshold (Patcher.java: lastEnd + 8).
mergeNearby :: ByteString -> [(Int, ByteString)] -> [(Int, ByteString)]
mergeNearby _ [] = []
mergeNearby _ [x] = [x]
mergeNearby modBs ((off1, d1) : (off2, d2) : rest)
  | gap <= 8 =
      mergeNearby modBs ((off1, merged) : rest)
  | otherwise = (off1, d1) : mergeNearby modBs ((off2, d2) : rest)
  where
    end1 = off1 + BS.length d1
    gap  = off2 - end1
    fill = BS.take gap (BS.drop end1 modBs)
    merged = d1 <> fill <> d2

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

-- | Human-readable summary of a PMSR patch.
pmsrInfo :: PMSRPatch -> String
pmsrInfo p = unlines $ filter (not . null)
  [ "format:      PMSR (Paper Mario Star Rod)"
  , "records:     " ++ show nRecs
  , "total bytes: " ++ show totalBytes
  , rangeStr
  ]
  where
    nRecs = length (pmsrRecords p)
    totalBytes = sum (map (BS.length . pmsrData) (pmsrRecords p))

    rangeStr
      | null (pmsrRecords p) = "range:       (empty patch)"
      | otherwise =
          let offsets = map pmsrOffset (pmsrRecords p)
              lo = minimum offsets
              hi = maximum offsets + fromIntegral (BS.length (pmsrData (last (pmsrRecords p))))
          in "range:       0x" ++ showHex (fromIntegral lo :: Word64) ""
             ++ " - 0x" ++ showHex (fromIntegral hi :: Word64) ""
