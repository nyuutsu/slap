{-# LANGUAGE OverloadedStrings #-}

module Slap.UPS.Parse
  ( parseUPS
  , parseUPSBody
  , parseBlocks
  ) where

-- Canonical reference: https://www.romhacking.net/documents/392/ (byuu UPS spec, near.sh mirror)

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..))
import Slap.Binary (getWord32LE)
import Slap.Checksum (CRC32(..))
import Slap.Error (SlapError(..))
import Slap.FFI (rustyCRC32)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, byuuVarint, atEnd, failGet)
import Slap.Measure (Length(..), FileSize(..), Delta(..))
import Control.Monad (when)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

parseUPS :: ByteString -> Either SlapError UPSPatch
parseUPS input
  | ByteString.length input < 4 =
      Left (InputTooShort LabelUPS (Length 4) (Length (ByteString.length input)))
  | ByteString.take 4 input /= "UPS1" =
      Left (BadMagic LabelUPS (ByteString.take 4 input))
  | ByteString.length input < 16 =
      Left (InputTooShort LabelUPS (Length 16) (Length (ByteString.length input)))
  | otherwise = do
      -- Validate patch CRC
      let storedPatchCRC = CRC32 (getWord32LE (ByteString.length input - 4) input)
          actualPatchCRC = rustyCRC32 (ByteString.take (ByteString.length input - 4) input)
      if storedPatchCRC /= actualPatchCRC
        then Left (PatchCRCMismatch LabelUPS storedPatchCRC actualPatchCRC)
        else pure ()
      let sourceCRC = CRC32 (getWord32LE (ByteString.length input - 12) input)
          targetCRC = CRC32 (getWord32LE (ByteString.length input - 8)  input)
          -- Parse body between magic and footer
          bodyBytes = ByteString.take (ByteString.length input - 16) (ByteString.drop 4 input)
      case runGet parseUPSBody bodyBytes of
        Left errorMessage -> Left (ParseError LabelUPS errorMessage)
        Right (sourceSize, targetSize, blocks) ->
          Right UPSPatch
            { upsSourceSize = sourceSize
            , upsTargetSize = targetSize
            , upsBlocks     = blocks
            , upsSourceCRC  = sourceCRC
            , upsTargetCRC  = targetCRC
            , upsPatchCRC   = storedPatchCRC
            }

parseUPSBody :: Get (FileSize, FileSize, [UPSBlock])
parseUPSBody = do
  rawSourceSize <- byuuVarint
  rawTargetSize <- byuuVarint
  when (rawSourceSize < 0) $ failGet "UPS: negative source size"
  when (rawTargetSize < 0) $ failGet "UPS: negative target size"
  blocks  <- parseBlocks
  pure (FileSize rawSourceSize, FileSize rawTargetSize, blocks)

parseBlocks :: Get [UPSBlock]
parseBlocks = do
  done <- atEnd
  if done then pure []
  else do
    skipCount <- Delta <$> byuuVarint
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
