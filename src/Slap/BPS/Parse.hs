{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Parse
  ( parseBPS
  , parseBPSBody
  , parseActions
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSBody(..), BPSAction(..), BPSMetadata(..),
                       decodeSignedVarint, isNegativeZeroSignedVarint,
                       bpsMagicBytes, bpsMagicLength, bpsCRC32Length, bpsFooterLength, bpsMinimumLength)
import Slap.Binary (getWord32LE, takeLength, dropLength, splitSuffixOfLength)
import Slap.Checksum (CRC32(..), ExpectedCRC32(..), ActualCRC32(..))
import Slap.Status (SlapError(..), SlapAdvisory(..), Parsed(..))
import Slap.FieldName (FieldName(..))
import Slap.FFI (crc32)
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, getBytes, byuuVarint, atEnd)
import Slap.Measure (Length(..), FileSize(..), Delta(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ParsedSizeValue(..), byteLength)

import Control.Monad (when)
import Data.Bits ((.&.), shiftR)
import qualified Data.Vector as Vector

parseBPS :: PatchFileContents -> Either SlapError (Parsed BPSPatch)
parseBPS (PatchFileContents input)
  | byteLength input < bpsMagicLength =
      Left (InputTooShort LabelBPS (RequiredLength bpsMagicLength) (ActualLength (byteLength input)))
  | actualMagicBytes /= bpsMagicBytes =
      Left (BadMagic LabelBPS (ActualMagic actualMagicBytes))
  | byteLength input < bpsMinimumLength =
      Left (InputTooShort LabelBPS (RequiredLength bpsMinimumLength) (ActualLength (byteLength input)))
  | otherwise = do
      -- The patch CRC covers everything except itself
      let (patchCRCCoverage, storedPatchCRCBytes) = splitSuffixOfLength bpsCRC32Length input
          storedPatchCRC = CRC32 (getWord32LE 0 storedPatchCRCBytes)
          actualPatchCRC = crc32 patchCRCCoverage
      when (storedPatchCRC /= actualPatchCRC) $
        Left (PatchCRCMismatch LabelBPS (ExpectedCRC32 storedPatchCRC) (ActualCRC32 actualPatchCRC))
      -- The footer is three CRC32s: source, target, patch
      let (bodyWithMagic, footerBytes) = splitSuffixOfLength bpsFooterLength input
          sourceCRC = CRC32 (getWord32LE 0 footerBytes)
          targetCRC = CRC32 (getWord32LE 4 footerBytes)
          -- Parse body between magic and footer
          bodyBytes = dropLength bpsMagicLength bodyWithMagic
      body <- runFormatParser LabelBPS parseBPSBody bodyBytes
      when (unFileSize (bpsBodySourceSize body) < 0) $
        Left (NegativeSize LabelBPS FieldSourceSize
          (ParsedSizeValue (unFileSize (bpsBodySourceSize body))))
      when (unFileSize (bpsBodyTargetSize body) < 0) $
        Left (NegativeSize LabelBPS FieldTargetSize
          (ParsedSizeValue (unFileSize (bpsBodyTargetSize body))))
      Right (Parsed
        BPSPatch
          { bpsSourceSize = bpsBodySourceSize body
          , bpsTargetSize = bpsBodyTargetSize body
          , bpsMetadata   = bpsBodyMetadata body
          , bpsActions    = Vector.fromList (bpsBodyActions body)
          , bpsSourceCRC  = sourceCRC
          , bpsTargetCRC  = targetCRC
          , bpsPatchCRC   = storedPatchCRC
          }
        (bpsBodyWarnings body))
  where
    actualMagicBytes = takeLength bpsMagicLength input

parseBPSBody :: ByteParser BPSBody
parseBPSBody = do
  rawSourceSize <- byuuVarint
  rawTargetSize <- byuuVarint
  let sourceSize = FileSize rawSourceSize
      targetSize = FileSize rawTargetSize
  metadataLength <- byuuVarint
  metadata       <- BPSMetadata <$> getBytes (Length metadataLength)
  parsedStream   <- parseActions
  pure BPSBody
    { bpsBodySourceSize = sourceSize
    , bpsBodyTargetSize = targetSize
    , bpsBodyMetadata   = metadata
    , bpsBodyActions    = parsedActionList parsedStream
    , bpsBodyWarnings   = parsedActionWarnings parsedStream
    }

----------------------------------------------------------------------------
-- Action stream walker
----------------------------------------------------------------------------

-- | The result of walking the BPS action stream:
-- the decoded actions in wire order, paired with any per-action warnings the walk accumulated.
-- The only warning emitted here is 'NegativeZeroInBPS'.
-- Strictly private to 'Slap.BPS.Parse' —
-- the public surface of 'BPSBody' carries the same two pieces of information through 'bpsBodyActions' and 'bpsBodyWarnings'.
data BPSParsedActionStream = BPSParsedActionStream
  { parsedActionList     :: ![BPSAction]
  , parsedActionWarnings :: ![SlapAdvisory]
  }

-- | One decoded action plus the warnings its decoding emitted.
-- 'decodeOneAction' returns this so the per-arm logic for the four BPS command codes lives in one helper,
-- leaving 'parseActions' as a thin tail-recursive walker that just stitches results into its two reversed accumulators.
data BPSDecodedAction = BPSDecodedAction
  { bpsDecodedActionValue    :: !BPSAction
  , bpsDecodedActionWarnings :: ![SlapAdvisory]
  }

-- | Which kind of copy action 'decodeCopyAction' is decoding.
data BPSCopyKind = CopyFromSource | CopyFromTarget

-- | Walk the BPS action stream until 'atEnd', returning every
-- successfully decoded action in wire order along with any warnings
-- the walk emitted.
--
-- The walker is tail-recursive with two reversed accumulators: actions, and per-action warning groups.
-- Each action's warnings enter as one group,
-- so an action that emits several keeps them in emission order through the final reverse-and-concat at the 'atEnd' boundary.
-- The per-action decoding is delegated to 'decodeOneAction' so the four-arm command-code dispatch has one home.
parseActions :: ByteParser BPSParsedActionStream
parseActions = walkActions [] []
  where
    walkActions :: [BPSAction] -> [[SlapAdvisory]] -> ByteParser BPSParsedActionStream
    walkActions accumulatedActionsReversed accumulatedWarningGroupsReversed = do
      done <- atEnd
      if done
        then pure BPSParsedActionStream
               { parsedActionList     = reverse accumulatedActionsReversed
               , parsedActionWarnings = concat (reverse accumulatedWarningGroupsReversed)
               }
        else do
          decodedAction <- decodeOneAction
          walkActions (bpsDecodedActionValue    decodedAction : accumulatedActionsReversed)
                      (bpsDecodedActionWarnings decodedAction : accumulatedWarningGroupsReversed)

-- | Decode a single BPS action: read the packed command-and-length
-- varint, dispatch on the two-bit command code, and consume each
-- variant's body. Wire values for the two-bit command code:
-- 0 = SourceRead, 1 = TargetRead, 2 = SourceCopy, 3 = TargetCopy.
decodeOneAction :: ByteParser BPSDecodedAction
decodeOneAction = do
  packedCommandAndLength <- byuuVarint
  let dataLength = Length (shiftR packedCommandAndLength 2 + 1)
  case packedCommandAndLength .&. 3 of
    0 -> pure BPSDecodedAction
           { bpsDecodedActionValue    = SourceRead dataLength
           , bpsDecodedActionWarnings = []
           }
    1 -> do
      payload <- getBytes dataLength
      pure BPSDecodedAction
        { bpsDecodedActionValue    = TargetRead payload
        , bpsDecodedActionWarnings = []
        }
    2 -> decodeCopyAction CopyFromSource dataLength
    _ -> decodeCopyAction CopyFromTarget dataLength

-- | Shared decoder for 'SourceCopy' and 'TargetCopy', whose wire
-- shapes differ only in their constructor: each consumes a
-- signed-delta varint following the packed command-and-length
-- header. The encoded varint is captured before decoding so the
-- @0x81@ negative-zero shape can be detected and surfaced as a
-- 'NegativeZeroInBPS' warning without re-reading the wire.
decodeCopyAction :: BPSCopyKind -> Length -> ByteParser BPSDecodedAction
decodeCopyAction copyKind dataLength = do
  offsetEncoded <- byuuVarint
  let delta = Delta (decodeSignedVarint offsetEncoded)
      action = case copyKind of
        CopyFromSource -> SourceCopy dataLength delta
        CopyFromTarget -> TargetCopy dataLength delta
  pure BPSDecodedAction
    { bpsDecodedActionValue    = action
    , bpsDecodedActionWarnings = [NegativeZeroInBPS | isNegativeZeroSignedVarint offsetEncoded]
    }
