{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.PMSR
  ( PMSRRecord(..)
  , PMSRPatch(..)
  , parsePMSR
  , applyPMSR
  , applyPMSRMemory
  , encodePMSR
  , pmsrMeta
  , pmsrInfo
  ) where

-- Canonical reference: Star Rod (Paper Mario 64 modding tool, Java, big-endian)
-- Best available spec: https://github.com/Sappharad/MultiPatch/issues/15 (Star Rod Discord quote)

import Patch.Get (Get, runGet, getBytes, skip, remaining)
import qualified Patch.Get as G

import Patch.Binary (copyBSRange)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)
import Data.Word (Word8, Word64)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
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
  mapM_ (applyOne h) (pmsrRecords patch)
  pure (length (pmsrRecords patch))
  where
    applyOne h r = do
      hSeek h AbsoluteSeek (fromIntegral (pmsrOffset r))
      BS.hPut h (pmsrData r)

-- | Apply a PMSR patch in memory: copy source, then overwrite at offsets.
applyPMSRMemory :: PMSRPatch -> ByteString -> ByteString
applyPMSRMemory patch source = unsafeCreate outLen $ \ptr -> do
    copyBSRange ptr 0 source 0 (min srcLen outLen)
    when (outLen > srcLen) $
      fillBytes (ptr `plusPtr` srcLen) (0 :: Word8) (outLen - srcLen)
    forM_ (pmsrRecords patch) $ \r ->
      copyBSRange ptr (fromIntegral (pmsrOffset r)) (pmsrData r) 0 (BS.length (pmsrData r))
  where
    srcLen = BS.length source
    outLen = foldl' max srcLen
      [ fromIntegral (pmsrOffset r) + BS.length (pmsrData r) | r <- pmsrRecords patch ]

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

-- | PMSR carries no header metadata; this returns an empty list.
pmsrMeta :: PMSRPatch -> [(String, String)]
pmsrMeta _ = []

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
          let recs = pmsrRecords p
              lo = minimum (map pmsrOffset recs)
              hi = maximum (map (\r -> pmsrOffset r + fromIntegral (BS.length (pmsrData r))) recs)
          in "range:       0x" ++ showHex (fromIntegral lo :: Word64) ""
             ++ " - 0x" ++ showHex (fromIntegral hi :: Word64) ""
