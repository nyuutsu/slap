{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Parse
  ( parseBPS
  , parseBPSBody
  , parseActions
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSBody(..), BPSAction(..), decodeSignedVarint,
                       bpsMagicSize, bpsFooterSize, bpsTotalOverhead)
import Slap.Binary (getWord32LE)
import Slap.Checksum (CRC32(..))
import Slap.Error (SlapError(..), FieldName(..))
import Slap.FFI (rustyCRC32)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getBytes, byuuVarint, atEnd)
import Slap.Measure (Length(..), FileSize(..), Delta(..))

import Data.Bits ((.&.), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

parseBPS :: ByteString -> Either SlapError BPSPatch
parseBPS input
  | ByteString.length input < bpsMagicSize =
      Left (InputTooShort LabelBPS (Length bpsMagicSize) (Length (ByteString.length input)))
  | ByteString.take bpsMagicSize input /= "BPS1" =
      Left (BadMagic LabelBPS (ByteString.take bpsMagicSize input))
  | ByteString.length input < bpsFooterSize =
      Left (InputTooShort LabelBPS (Length bpsFooterSize) (Length (ByteString.length input)))
  | otherwise = do
      -- Validate patch CRC (covers everything except the last 4 bytes)
      let storedPatchCRC = CRC32 (getWord32LE (ByteString.length input - 4) input)
          actualPatchCRC = rustyCRC32 (ByteString.take (ByteString.length input - 4) input)
      if storedPatchCRC /= actualPatchCRC
        then Left (PatchCRCMismatch LabelBPS storedPatchCRC actualPatchCRC)
        else pure ()
      let sourceCRC = CRC32 (getWord32LE (ByteString.length input - bpsFooterSize) input)
          targetCRC = CRC32 (getWord32LE (ByteString.length input - 8)  input)
          -- Parse body between magic and footer using Get monad
          bodyBytes = ByteString.take (ByteString.length input - bpsTotalOverhead) (ByteString.drop bpsMagicSize input)
      case runGet parseBPSBody bodyBytes of
        Left errorMessage -> Left (ParseError LabelBPS errorMessage)
        Right body
          | unFileSize (bpsBodySourceSize body) < 0 ->
              Left (NegativeSize LabelBPS FieldSourceSize
                (unFileSize (bpsBodySourceSize body)))
          | unFileSize (bpsBodyTargetSize body) < 0 ->
              Left (NegativeSize LabelBPS FieldTargetSize
                (unFileSize (bpsBodyTargetSize body)))
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
      3 -> TargetCopy (Length dataLength) . Delta . fromIntegral . decodeSignedVarint <$> byuuVarint
      _ -> error "unreachable"  -- (.&. 3) is always 0-3; GHC can't see this
    remaining <- parseActions
    pure (action : remaining)
