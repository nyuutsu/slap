{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Parse
  ( parseAPSGBA
  , parseGBA
  , parseGBARecords
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/APS-(GBA)
-- Secondary: RomPatcher.js modules/RomPatcher.format.aps_gba.js

import Slap.APSGBA.Types
import Slap.Checksum (CRC16(..))
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getBytes, skip, remaining, word16LE, word32LE)
import Slap.Measure (Length(..), FileSize(..), Offset(..))

import qualified Data.ByteString as ByteString

parseAPSGBA :: ByteString.ByteString -> Either SlapError APSGBAPatch
parseAPSGBA input
  | ByteString.length input < 4 =
      Left (InputTooShort LabelAPSGBA (Length 4) (Length (ByteString.length input)))
  | ByteString.take 4 input /= "APS1" =
      Left (BadMagic LabelAPSGBA (ByteString.take 4 input))
  | otherwise =
      case runGet parseGBA input of
        Left errorMessage -> Left (ParseError LabelAPSGBA errorMessage)
        Right patch -> Right patch

parseGBA :: Get APSGBAPatch
parseGBA = do
  skip (Length 4)  -- "APS1"
  sourceSize <- FileSize . fromIntegral <$> word32LE
  targetSize <- FileSize . fromIntegral <$> word32LE
  records <- parseGBARecords
  pure $ APSGBAPatch (APSGBAHeader sourceSize targetSize) records

parseGBARecords :: Get [APSGBARecord]
parseGBARecords = do
  remainingLength <- remaining
  if unLength remainingLength < apsGbaRecordSize then pure []
  else do
    offset <- Offset . fromIntegral <$> word32LE
    sourceCrc <- CRC16 <$> word16LE
    targetCrc <- CRC16 <$> word16LE
    xorPayload <- getBytes (Length apsGbaBlockSize)
    rest <- parseGBARecords
    pure (APSGBARecord offset sourceCrc targetCrc xorPayload : rest)
