{-# LANGUAGE OverloadedStrings #-}

module Slap.UPS.Parse
  ( parseUPS
  , parseUPSBody
  , parseBlocks
  ) where

-- Canonical reference: https://www.romhacking.net/documents/392/ (byuu UPS spec, near.sh mirror)

import Slap.UPS.Types (UPSPatch(..), UPSBody(..), UPSBlock(..),
                       upsMagicSize, upsCRC32Size, upsFooterSize, upsTotalOverhead)
import Slap.Binary (getWord32LE)
import Slap.Checksum (CRC32(..), ExpectedCRC32(..), ActualCRC32(..))
import Slap.Error (SlapError(..), FieldName(..))
import Slap.FFI (rustyCRC32)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getUntilByte, byuuVarint, atEnd)
import Slap.Measure (Length(..), FileSize(..), Delta(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ParsedSizeValue(..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

parseUPS :: ByteString -> Either SlapError UPSPatch
parseUPS input
  | ByteString.length input < upsMagicSize =
      Left (InputTooShort LabelUPS (RequiredLength (Length upsMagicSize)) (ActualLength (Length (ByteString.length input))))
  | ByteString.take upsMagicSize input /= "UPS1" =
      Left (BadMagic LabelUPS (ActualMagic (ByteString.take upsMagicSize input)))
  | ByteString.length input < upsTotalOverhead =
      Left (InputTooShort LabelUPS (RequiredLength (Length upsTotalOverhead)) (ActualLength (Length (ByteString.length input))))
  | otherwise = do
      -- Validate patch CRC
      let storedPatchCRC = CRC32 (getWord32LE (ByteString.length input - upsCRC32Size) input)
          actualPatchCRC = rustyCRC32 (ByteString.take (ByteString.length input - upsCRC32Size) input)
      if storedPatchCRC /= actualPatchCRC
        then Left (PatchCRCMismatch LabelUPS (ExpectedCRC32 storedPatchCRC) (ActualCRC32 actualPatchCRC))
        else pure ()
      let sourceCRC = CRC32 (getWord32LE (ByteString.length input - upsFooterSize) input)
          targetCRC = CRC32 (getWord32LE (ByteString.length input - 2 * upsCRC32Size) input)
          -- Parse body between magic and footer
          bodyBytes = ByteString.take (ByteString.length input - upsTotalOverhead) (ByteString.drop upsMagicSize input)
      case runGet parseUPSBody bodyBytes of
        Left errorMessage -> Left (ParseError LabelUPS errorMessage)
        Right body
          | unFileSize (upsBodySourceSize body) < 0 ->
              Left (NegativeSize LabelUPS FieldSourceSize
                (ParsedSizeValue (unFileSize (upsBodySourceSize body))))
          | unFileSize (upsBodyTargetSize body) < 0 ->
              Left (NegativeSize LabelUPS FieldTargetSize
                (ParsedSizeValue (unFileSize (upsBodyTargetSize body))))
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
  -- parseBlocks builds a cons-cell list inside the pure Get monad
  -- (where list spine is cheap and natural). We materialise to Vector
  -- once at the UPSBody boundary so the apply loop can index by
  -- position — same pattern as BPS/Parse.hs's action vector.
  blocks  <- parseBlocks
  pure UPSBody
    { upsBodySourceSize = FileSize (fromIntegral rawSourceSize)
    , upsBodyTargetSize = FileSize (fromIntegral rawTargetSize)
    , upsBodyBlocks     = Vector.fromList blocks
    }

parseBlocks :: Get [UPSBlock]
parseBlocks = do
  done <- atEnd
  if done then pure []
  else do
    skipCount <- Delta . fromIntegral <$> byuuVarint
    xorData   <- getUntilByte 0x00
    remaining <- parseBlocks
    pure (UPSBlock skipCount xorData : remaining)
