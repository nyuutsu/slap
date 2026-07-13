{-# LANGUAGE OverloadedStrings #-}

module Slap.UPS.Parse
  ( parseUPS
  , parseUPSBody
  , parseBlocks
  ) where

-- Canonical reference: https://www.romhacking.net/documents/392/ (byuu UPS spec, near.sh mirror)

import Slap.UPS.Types (UPSPatch(..), UPSBody(..), UPSBlock(..),
                       upsMagicBytes, upsMagicLength, upsCRC32Length, upsFooterLength, upsOverheadLength)
import Slap.Binary (getWord32LE)
import Slap.Checksum (CRC32(..), ExpectedCRC32(..), ActualCRC32(..))
import Slap.Status (SlapError(..), Parsed(..))
import Slap.FieldName (FieldName(..))
import Slap.FFI (crc32)
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, getUntilByte, byuuVarint, atEnd)
import Slap.Measure (lengthToInt, Length(..), FileSize(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ParsedSizeValue(..), byteLength)
import Control.Monad (when)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

parseUPS :: PatchFileContents -> Either SlapError (Parsed UPSPatch)
parseUPS (PatchFileContents input)
  | ByteString.length input < lengthToInt upsMagicLength =
      Left (InputTooShort LabelUPS (RequiredLength upsMagicLength) (ActualLength (byteLength input)))
  | ByteString.take (lengthToInt upsMagicLength) input /= upsMagicBytes =
      Left (BadMagic LabelUPS (ActualMagic (ByteString.take (lengthToInt upsMagicLength) input)))
  | ByteString.length input < lengthToInt upsOverheadLength =
      Left (InputTooShort LabelUPS (RequiredLength upsOverheadLength) (ActualLength (byteLength input)))
  | otherwise = do
      -- Validate patch CRC
      let inputLength    = ByteString.length input
          crcLength      = lengthToInt upsCRC32Length
          footerLength   = lengthToInt upsFooterLength
          overheadLength = lengthToInt upsOverheadLength
          magicLength    = lengthToInt upsMagicLength
          storedPatchCRC = CRC32 (getWord32LE (inputLength - crcLength) input)
          actualPatchCRC = crc32 (ByteString.take (inputLength - crcLength) input)
      when (storedPatchCRC /= actualPatchCRC) $
        Left (PatchCRCMismatch LabelUPS (ExpectedCRC32 storedPatchCRC) (ActualCRC32 actualPatchCRC))
      let sourceCRC = CRC32 (getWord32LE (inputLength - footerLength) input)
          targetCRC = CRC32 (getWord32LE (inputLength - 2 * crcLength) input)
          -- Parse body between magic and footer
          bodyBytes = ByteString.take (inputLength - overheadLength) (ByteString.drop magicLength input)
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
    { upsBodySourceSize = FileSize (fromIntegral rawSourceSize)
    , upsBodyTargetSize = FileSize (fromIntegral rawTargetSize)
    , upsBodyBlocks     = Vector.fromList blocks
    }

parseBlocks :: ByteParser [UPSBlock]
parseBlocks = do
  done <- atEnd
  if done then pure []
  else do
    skipCount <- Length . fromIntegral <$> byuuVarint
    xorData   <- getUntilByte 0x00
    remaining <- parseBlocks
    pure (UPSBlock skipCount xorData : remaining)
