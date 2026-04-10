{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Parse
  ( parseBPS
  , parseBPSBody
  , parseActions
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSBody(..), BPSAction(..), decodeSignedVarint,
                       bpsMagicLength, bpsCRC32Length, bpsFooterLength, bpsOverheadLength)
import Slap.Binary (getWord32LE)
import Slap.Checksum (CRC32(..), ExpectedCRC32(..), ActualCRC32(..))
import Slap.Error (SlapError(..), FieldName(..))
import Slap.FFI (rustyCRC32)
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getBytes, byuuVarint, atEnd)
import Slap.Measure (Length(..), FileSize(..), Delta(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ParsedSizeValue(..))

import Data.Bits ((.&.), shiftR)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

parseBPS :: PatchFileContents -> Either SlapError BPSPatch
parseBPS (PatchFileContents input)
  | ByteString.length input < unLength bpsMagicLength =
      Left (InputTooShort LabelBPS (RequiredLength bpsMagicLength) (ActualLength (Length (ByteString.length input))))
  | ByteString.take (unLength bpsMagicLength) input /= "BPS1" =
      Left (BadMagic LabelBPS (ActualMagic (ByteString.take (unLength bpsMagicLength) input)))
  | ByteString.length input < unLength bpsFooterLength =
      Left (InputTooShort LabelBPS (RequiredLength bpsFooterLength) (ActualLength (Length (ByteString.length input))))
  | otherwise = do
      -- Validate patch CRC (covers everything except the trailing patch CRC)
      let inputLength    = ByteString.length input
          crcLength      = unLength bpsCRC32Length
          footerLength   = unLength bpsFooterLength
          overheadLength = unLength bpsOverheadLength
          magicLength    = unLength bpsMagicLength
          storedPatchCRC = CRC32 (getWord32LE (inputLength - crcLength) input)
          actualPatchCRC = rustyCRC32 (ByteString.take (inputLength - crcLength) input)
      if storedPatchCRC /= actualPatchCRC
        then Left (PatchCRCMismatch LabelBPS (ExpectedCRC32 storedPatchCRC) (ActualCRC32 actualPatchCRC))
        else pure ()
      let sourceCRC = CRC32 (getWord32LE (inputLength - footerLength) input)
          targetCRC = CRC32 (getWord32LE (inputLength - 2 * crcLength) input)
          -- Parse body between magic and footer using Get monad
          bodyBytes = ByteString.take (inputLength - overheadLength) (ByteString.drop magicLength input)
      case runGet parseBPSBody bodyBytes of
        Left errorMessage -> Left (ParseError LabelBPS errorMessage)
        Right body
          | unFileSize (bpsBodySourceSize body) < 0 ->
              Left (NegativeSize LabelBPS FieldSourceSize
                (ParsedSizeValue (unFileSize (bpsBodySourceSize body))))
          | unFileSize (bpsBodyTargetSize body) < 0 ->
              Left (NegativeSize LabelBPS FieldTargetSize
                (ParsedSizeValue (unFileSize (bpsBodyTargetSize body))))
          | otherwise ->
              Right BPSPatch
                { bpsSourceSize = bpsBodySourceSize body
                , bpsTargetSize = bpsBodyTargetSize body
                , bpsMetadata   = bpsBodyMetadata body
                -- The parser builds the action stream as a list (cheap
                -- cons during 'parseActions'); we materialise it into
                -- one contiguous 'Vector' here at the boundary so the
                -- intermediate cons cells become collectable as soon as
                -- the BPSPatch escapes this scope.
                , bpsActions    = Vector.fromList (bpsBodyActions body)
                , bpsSourceCRC  = sourceCRC
                , bpsTargetCRC  = targetCRC
                , bpsPatchCRC   = storedPatchCRC
                }

parseBPSBody :: Get BPSBody
parseBPSBody = do
  rawSourceSize <- byuuVarint
  rawTargetSize <- byuuVarint
  let sourceSize = FileSize (fromIntegral rawSourceSize)
      targetSize = FileSize (fromIntegral rawTargetSize)
  metadataLength <- fromIntegral <$> byuuVarint
  metadata       <- getBytes (Length metadataLength)
  actions <- parseActions
  pure BPSBody
    { bpsBodySourceSize = sourceSize
    , bpsBodyTargetSize = targetSize
    , bpsBodyMetadata   = metadata
    , bpsBodyActions    = actions
    }

parseActions :: Get [BPSAction]
parseActions = do
  done <- atEnd
  if done then pure []
  else do
    encoded <- byuuVarint
    let commandCode = encoded .&. 3
        dataLength = fromIntegral (shiftR encoded 2) + 1
    action <- case commandCode of
      0 -> pure (SourceRead (Length dataLength))
      1 -> TargetRead <$> getBytes (Length dataLength)
      2 -> SourceCopy (Length dataLength) . Delta . fromIntegral . decodeSignedVarint <$> byuuVarint
      _ -> TargetCopy (Length dataLength) . Delta . fromIntegral . decodeSignedVarint <$> byuuVarint
    remaining <- parseActions
    pure (action : remaining)
