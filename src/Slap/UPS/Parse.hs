{-# LANGUAGE OverloadedStrings #-}

module Slap.UPS.Parse
  ( parseUPS
  , parseUPSBody
  , parseBlocks
  ) where

-- Canonical reference: https://www.romhacking.net/documents/392/ (byuu UPS spec, near.sh mirror)

import Slap.UPS.Types (UPSPatch(..), UPSBody(..), UPSBlock(..),
                       upsMagicSize, upsFooterSize, upsTotalOverhead)
import Slap.Binary (getWord32LE)
import Slap.Checksum (CRC32(..))
import Slap.Error (SlapError(..), FieldName(..))
import Slap.FFI (rustyCRC32)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, byuuVarint, atEnd)
import Slap.Measure (Length(..), FileSize(..), Delta(..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

parseUPS :: ByteString -> Either SlapError UPSPatch
parseUPS input
  | ByteString.length input < upsMagicSize =
      Left (InputTooShort LabelUPS (Length upsMagicSize) (Length (ByteString.length input)))
  | ByteString.take upsMagicSize input /= "UPS1" =
      Left (BadMagic LabelUPS (ByteString.take upsMagicSize input))
  | ByteString.length input < upsTotalOverhead =
      Left (InputTooShort LabelUPS (Length upsTotalOverhead) (Length (ByteString.length input)))
  | otherwise = do
      -- Validate patch CRC
      let storedPatchCRC = CRC32 (getWord32LE (ByteString.length input - 4) input)
          actualPatchCRC = rustyCRC32 (ByteString.take (ByteString.length input - 4) input)
      if storedPatchCRC /= actualPatchCRC
        then Left (PatchCRCMismatch LabelUPS storedPatchCRC actualPatchCRC)
        else pure ()
      let sourceCRC = CRC32 (getWord32LE (ByteString.length input - upsFooterSize) input)
          targetCRC = CRC32 (getWord32LE (ByteString.length input - 8)  input)
          -- Parse body between magic and footer
          bodyBytes = ByteString.take (ByteString.length input - upsTotalOverhead) (ByteString.drop upsMagicSize input)
      case runGet parseUPSBody bodyBytes of
        Left errorMessage -> Left (ParseError LabelUPS errorMessage)
        Right body
          | unFileSize (upsBodySourceSize body) < 0 ->
              Left (NegativeSize LabelUPS FieldSourceSize
                (fromIntegral (unFileSize (upsBodySourceSize body))))
          | unFileSize (upsBodyTargetSize body) < 0 ->
              Left (NegativeSize LabelUPS FieldTargetSize
                (fromIntegral (unFileSize (upsBodyTargetSize body))))
          | otherwise ->
              Right UPSPatch
                { upsSourceSize = upsBodySourceSize body
                , upsTargetSize = upsBodyTargetSize body
                , upsBlocks     = upsBodyBlocks body
                , upsSourceCRC  = sourceCRC
                , upsTargetCRC  = targetCRC
                , upsPatchCRC   = storedPatchCRC
                }

parseUPSBody :: Get UPSBody
parseUPSBody = do
  rawSourceSize <- byuuVarint
  rawTargetSize <- byuuVarint
  blocks  <- parseBlocks
  pure UPSBody
    { upsBodySourceSize = FileSize (fromIntegral rawSourceSize)
    , upsBodyTargetSize = FileSize (fromIntegral rawTargetSize)
    , upsBodyBlocks     = blocks
    }

parseBlocks :: Get [UPSBlock]
parseBlocks = do
  done <- atEnd
  if done then pure []
  else do
    skipCount <- Delta . fromIntegral <$> byuuVarint
    xorBytes <- collectXor []
    remaining <- parseBlocks
    pure (UPSBlock skipCount xorBytes : remaining)
  where
    -- Collect nonzero XOR bytes until 0x00 terminator
    collectXor accumulated = do
      byte <- getByte
      if byte == 0x00
        then pure (ByteString.pack (reverse accumulated))
        else collectXor (byte : accumulated)
