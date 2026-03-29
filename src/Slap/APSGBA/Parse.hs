{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Parse
  ( parseAPSGBA
  , parseGBA
  , parseGBARecords
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/APS-(GBA)
-- Secondary: RomPatcher.js modules/RomPatcher.format.aps_gba.js

import Slap.APSGBA.Types
import Slap.Get (Get, runGet, getBytes, skip, remaining, word16LE, word32LE)
import Slap.Measure (Length(..))

import qualified Data.ByteString as ByteString

parseAPSGBA :: ByteString.ByteString -> Either String APSGBAPatch
parseAPSGBA input
  | ByteString.length input < 4 = Left "APS-GBA: input too short"
  | ByteString.take 4 input /= "APS1" = Left "not an APS-GBA file (bad magic)"
  | otherwise = runGet parseGBA input

parseGBA :: Get APSGBAPatch
parseGBA = do
  skip (Length 4)  -- "APS1"
  sourceSize <- word32LE
  targetSize <- word32LE
  records <- parseGBARecords
  pure $ APSGBAPatch (APSGBAHeader sourceSize targetSize) records

parseGBARecords :: Get [APSGBARecord]
parseGBARecords = do
  remainingLength <- remaining
  if unLength remainingLength < 65544 then pure []
  else do
    offset <- word32LE
    sourceCrc <- word16LE
    targetCrc <- word16LE
    xorPayload <- getBytes (Length 65536)
    rest <- parseGBARecords
    pure (APSGBARecord offset sourceCrc targetCrc xorPayload : rest)
