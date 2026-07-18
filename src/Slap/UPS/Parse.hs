{-# LANGUAGE OverloadedStrings #-}

module Slap.UPS.Parse
  ( parseUPS
  , parseUPSBody
  , parseBlocks
  ) where

-- Canonical reference: https://www.romhacking.net/documents/392/ (byuu UPS spec, near.sh mirror)

import Slap.UPS.Types (UPSPatch(..), UPSBody(..), UPSBlock(..),
                       upsMagicBytes, upsMagicLength, upsCRC32Length, upsFooterLength, upsOverheadLength)
import Slap.Binary (getWord32LE, takeLength, dropLength, splitSuffixOfLength)
import Slap.Checksum (CRC32(..), ExpectedCRC32(..), ActualCRC32(..))
import Slap.Status (SlapError(..), Parsed(..))
import Slap.FieldName (FieldName(..))
import Slap.FFI (crc32)
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, getUntilByte, byuuVarint, atEnd)
import Slap.Measure (Length(..), FileSize(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ParsedSizeValue(..), byteLength)
import Control.Monad (when)
import qualified Data.Vector as Vector

parseUPS :: PatchFileContents -> Either SlapError (Parsed UPSPatch)
parseUPS (PatchFileContents input)
  | byteLength input < upsMagicLength =
      Left (InputTooShort LabelUPS (RequiredLength upsMagicLength) (ActualLength (byteLength input)))
  | actualMagicBytes /= upsMagicBytes =
      Left (BadMagic LabelUPS (ActualMagic actualMagicBytes))
  | byteLength input < upsOverheadLength =
      Left (InputTooShort LabelUPS (RequiredLength upsOverheadLength) (ActualLength (byteLength input)))
  | otherwise = do
      -- The patch CRC covers everything except itself
      let (patchCRCCoverage, storedPatchCRCBytes) = splitSuffixOfLength upsCRC32Length input
          storedPatchCRC = CRC32 (getWord32LE 0 storedPatchCRCBytes)
          actualPatchCRC = crc32 patchCRCCoverage
      when (storedPatchCRC /= actualPatchCRC) $
        Left (PatchCRCMismatch LabelUPS (ExpectedCRC32 storedPatchCRC) (ActualCRC32 actualPatchCRC))
      -- The footer is three CRC32s: source, target, patch
      let (bodyWithMagic, footerBytes) = splitSuffixOfLength upsFooterLength input
          sourceCRC = CRC32 (getWord32LE 0 footerBytes)
          targetCRC = CRC32 (getWord32LE 4 footerBytes)
          -- Parse body between magic and footer
          bodyBytes = dropLength upsMagicLength bodyWithMagic
      body <- runFormatParser LabelUPS parseUPSBody bodyBytes
      when (unFileSize (upsBodySourceSize body) < 0) $
        Left (NegativeSize LabelUPS FieldSourceSize
          (ParsedSizeValue (unFileSize (upsBodySourceSize body))))
      when (unFileSize (upsBodyTargetSize body) < 0) $
        Left (NegativeSize LabelUPS FieldTargetSize
          (ParsedSizeValue (unFileSize (upsBodyTargetSize body))))
      Right (Parsed
        UPSPatch
          { upsSourceSize = upsBodySourceSize body
          , upsTargetSize = upsBodyTargetSize body
          , upsBlocks     = upsBodyBlocks body
          , upsSourceCRC  = sourceCRC
          , upsTargetCRC  = targetCRC
          , upsPatchCRC   = storedPatchCRC
          }
        [])
  where
    actualMagicBytes = takeLength upsMagicLength input

parseUPSBody :: ByteParser UPSBody
parseUPSBody = do
  rawSourceSize <- byuuVarint
  rawTargetSize <- byuuVarint
  -- parseBlocks builds a cons-cell list inside 'ByteParser'
  -- (where list spine is cheap and natural). We materialise to Vector
  -- once at the UPSBody boundary so the apply loop can index by
  -- position — same pattern as BPS/Parse.hs's action vector.
  blocks  <- parseBlocks
  pure UPSBody
    { upsBodySourceSize = FileSize rawSourceSize
    , upsBodyTargetSize = FileSize rawTargetSize
    , upsBodyBlocks     = Vector.fromList blocks
    }

parseBlocks :: ByteParser [UPSBlock]
parseBlocks = do
  done <- atEnd
  if done then pure []
  else do
    skipCount <- Length <$> byuuVarint
    xorData   <- getUntilByte 0x00
    remaining <- parseBlocks
    pure (UPSBlock skipCount xorData : remaining)
