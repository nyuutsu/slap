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
import qualified Patch.Get as Get

import Patch.Binary (copyByteStringRange)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as LazyByteString
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
parsePMSR input
  | ByteString.length input < 4 = Left "PMSR: input too short"
  | ByteString.take 4 input /= "PMSR" = Left "not a PMSR file (bad magic)"
  | otherwise = runGet parsePMSRBody input

parsePMSRBody :: Get PMSRPatch
parsePMSRBody = do
  skip 4  -- magic
  count <- fromIntegral <$> Get.word32BE
  records  <- parseLoop count []
  pure (PMSRPatch records)

parseLoop :: Int -> [PMSRRecord] -> Get [PMSRRecord]
parseLoop 0 accumulated = pure (reverse accumulated)
parseLoop count accumulated = do
  offset <- fromIntegral <$> Get.word32BE
  dataLength <- fromIntegral <$> Get.word32BE
  available <- remaining
  if dataLength > available
    then fail ("PMSR record needs " ++ show dataLength ++ " bytes but only "
               ++ show available ++ " available")
    else do
      payload <- getBytes dataLength
      parseLoop (count - 1) (PMSRRecord offset payload : accumulated)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyPMSR :: PMSRPatch -> FilePath -> IO Int
applyPMSR patch target = withBinaryFile target ReadWriteMode $ \handle -> do
  mapM_ (applyRecord handle) (pmsrRecords patch)
  pure (length (pmsrRecords patch))
  where
    applyRecord handle record = do
      hSeek handle AbsoluteSeek (fromIntegral (pmsrOffset record))
      ByteString.hPut handle (pmsrData record)

-- | Apply a PMSR patch in memory: copy source, then overwrite at offsets.
applyPMSRMemory :: PMSRPatch -> ByteString -> ByteString
applyPMSRMemory patch source = unsafeCreate outputSize $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength outputSize)
    when (outputSize > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
    forM_ (pmsrRecords patch) $ \record ->
      copyByteStringRange targetPointer (fromIntegral (pmsrOffset record)) (pmsrData record) 0 (ByteString.length (pmsrData record))
  where
    sourceLength = ByteString.length source
    outputSize = foldl' max sourceLength
      [ fromIntegral (pmsrOffset record) + ByteString.length (pmsrData record) | record <- pmsrRecords patch ]

encodePMSR :: [(Int, ByteString)] -> ByteString
encodePMSR records = LazyByteString.toStrict $ toLazyByteString $
    byteString "PMSR"
    <> word32BE (fromIntegral (length records))
    <> foldMap encodeRecord records
  where
    encodeRecord (offset, payload) =
      word32BE (fromIntegral offset)
      <> word32BE (fromIntegral (ByteString.length payload))
      <> byteString payload

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

-- | PMSR carries no header metadata; this returns an empty list.
pmsrMeta :: PMSRPatch -> [(String, String)]
pmsrMeta _ = []

pmsrInfo :: PMSRPatch -> String
pmsrInfo patch = unlines $ filter (not . null)
  [ "format:      PMSR (Paper Mario Star Rod)"
  , "records:     " ++ show recordCount
  , "total bytes: " ++ show totalBytes
  , rangeString
  ]
  where
    recordCount = length (pmsrRecords patch)
    totalBytes = sum (map (ByteString.length . pmsrData) (pmsrRecords patch))

    rangeString
      | null (pmsrRecords patch) = "range:       (empty patch)"
      | otherwise =
          let records = pmsrRecords patch
              lowest = minimum (map pmsrOffset records)
              highest = maximum (map (\record -> pmsrOffset record + fromIntegral (ByteString.length (pmsrData record))) records)
          in "range:       0x" ++ showHex (fromIntegral lowest :: Word64) ""
             ++ " - 0x" ++ showHex (fromIntegral highest :: Word64) ""
