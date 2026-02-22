{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.PMSR
  ( PMSRRecord(..)
  , PMSRPatch(..)
  , parsePMSR
  , applyPMSR
  , encodePMSR
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

-- Format: 4 bytes "PMSR" magic, uint32BE record count,
-- then for each record: uint32BE offset, uint32BE length, then data bytes.
-- Star Rod (Java) uses big-endian — this is the authoritative producer.
parsePMSR :: ByteString -> Either String PMSRPatch
parsePMSR bs
  | BS.length bs < 4 = Left "PMSR: input too short"
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

applyPMSR :: PMSRPatch -> FilePath -> IO Int
applyPMSR patch target = withBinaryFile target ReadWriteMode $ \h -> do
  go h 0 (pmsrRecords patch)
  where
    go _ n [] = pure n
    go h n (r:rs) = do
      hSeek h AbsoluteSeek (fromIntegral (pmsrOffset r))
      BS.hPut h (pmsrData r)
      go h (n + 1) rs

encodePMSR :: [(Int, ByteString)] -> ByteString
encodePMSR recs = BL.toStrict $ toLazyByteString $
    byteString "PMSR"
    <> word32BE (fromIntegral (length recs))
    <> foldMap encodeRec recs
  where
    encodeRec (off, dat) =
      word32BE (fromIntegral off)
      <> word32BE (fromIntegral (BS.length dat))
      <> byteString dat

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

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
