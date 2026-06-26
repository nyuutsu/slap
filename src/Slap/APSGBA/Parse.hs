{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Parse
  ( parseAPSGBA
  , parseGBA
  , parseGBARecords
  , isAPSGBAStructured
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/APS-(GBA)
-- Secondary: RomPatcher.js modules/RomPatcher.format.aps_gba.js

import Slap.APSGBA.Types (APSGBAPatch(..), APSGBAHeader(..), APSGBARecord(..),
                           apsGbaMagicBytes, apsGbaBlockSize, apsGbaRecordSize,
                           apsGbaHeaderSize)
import Slap.Checksum (CRC16(..))
import Slap.Status (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runByteParser, getBytes, skip, remaining, word16LE, word32LE)
import Slap.Measure (Length(..), FileSize(..), offsetFromParsed,
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     byteLength)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

-- | Structural check for APS-GBA: a header followed by N 65544-byte records, each at a 64KB-aligned offset.
-- Used to disambiguate "APS10" (APSN64) from "APS1" + source_size when size mod 256 == 48.
isAPSGBAStructured :: ByteString -> Bool
isAPSGBAStructured input =
  let dataLength   = ByteString.length input - apsGbaHeaderSize
      recordCount  = dataLength `div` apsGbaRecordSize
      recordOffsetIs64KBAligned recordIndex =
        let recordHeaderStart = apsGbaHeaderSize + recordIndex * apsGbaRecordSize
        in ByteString.index input recordHeaderStart == 0
           && ByteString.index input (recordHeaderStart + 1) == 0
  in dataLength == 0
     || (dataLength >= apsGbaRecordSize && dataLength `mod` apsGbaRecordSize == 0
         && all recordOffsetIs64KBAligned [0 .. recordCount - 1])

parseAPSGBA :: PatchFileContents -> Either SlapError (Parsed APSGBAPatch)
parseAPSGBA (PatchFileContents input)
  | ByteString.length input < 4 =
      Left (InputTooShort LabelAPSGBA (RequiredLength (Length 4)) (ActualLength (byteLength input)))
  | ByteString.take 4 input /= apsGbaMagicBytes =
      Left (BadMagic LabelAPSGBA (ActualMagic (ByteString.take 4 input)))
  | otherwise =
      case runByteParser parseGBA input of
        Left parserError -> Left (ParseError LabelAPSGBA parserError)
        Right patch -> Right (Parsed patch [])

parseGBA :: ByteParser APSGBAPatch
parseGBA = do
  skip (Length 4)  -- "APS1"
  sourceSize <- FileSize . fromIntegral <$> word32LE
  targetSize <- FileSize . fromIntegral <$> word32LE
  records <- parseGBARecords
  pure $ APSGBAPatch (APSGBAHeader sourceSize targetSize) records

parseGBARecords :: ByteParser [APSGBARecord]
parseGBARecords = do
  remainingLength <- remaining
  if unLength remainingLength < apsGbaRecordSize then pure []
  else do
    offset <- offsetFromParsed <$> word32LE
    sourceCrc <- CRC16 <$> word16LE
    targetCrc <- CRC16 <$> word16LE
    xorPayload <- getBytes (Length apsGbaBlockSize)
    rest <- parseGBARecords
    pure (APSGBARecord offset sourceCrc targetCrc xorPayload : rest)
