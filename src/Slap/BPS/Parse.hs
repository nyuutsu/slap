{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Parse
  ( parseBPS
  , parseBPSBody
  , parseActions
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSBody(..), BPSAction(..), BPSMetadata(..),
                       decodeSignedVarint, isNegativeZeroSignedVarint,
                       bpsMagicBytes, bpsMagicLength, bpsCRC32Length, bpsFooterLength, bpsOverheadLength)
import Slap.Binary (getWord32LE)
import Slap.Checksum (CRC32(..), ExpectedCRC32(..), ActualCRC32(..))
import Slap.Status (SlapError(..), SlapAdvisory(..), Parsed(..))
import Slap.FieldName (FieldName(..))
import Slap.FFI (crc32)
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runByteParser, getBytes, byuuVarint, atEnd)
import Slap.Measure (Length(..), FileSize(..), Delta(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), ParsedSizeValue(..), byteLength)

import Data.Bits ((.&.), shiftR)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

parseBPS :: PatchFileContents -> Either SlapError (Parsed BPSPatch)
parseBPS (PatchFileContents input)
  | ByteString.length input < unLength bpsMagicLength =
      Left (InputTooShort LabelBPS (RequiredLength bpsMagicLength) (ActualLength (byteLength input)))
  | ByteString.take (unLength bpsMagicLength) input /= bpsMagicBytes =
      Left (BadMagic LabelBPS (ActualMagic (ByteString.take (unLength bpsMagicLength) input)))
  | ByteString.length input < unLength bpsFooterLength =
      Left (InputTooShort LabelBPS (RequiredLength bpsFooterLength) (ActualLength (byteLength input)))
  | otherwise = do
      -- Validate patch CRC (covers everything except the trailing patch CRC)
      let inputLength    = ByteString.length input
          crcLength      = unLength bpsCRC32Length
          footerLength   = unLength bpsFooterLength
          overheadLength = unLength bpsOverheadLength
          magicLength    = unLength bpsMagicLength
          storedPatchCRC = CRC32 (getWord32LE (inputLength - crcLength) input)
          actualPatchCRC = crc32 (ByteString.take (inputLength - crcLength) input)
      if storedPatchCRC /= actualPatchCRC
        then Left (PatchCRCMismatch LabelBPS (ExpectedCRC32 storedPatchCRC) (ActualCRC32 actualPatchCRC))
        else pure ()
      let sourceCRC = CRC32 (getWord32LE (inputLength - footerLength) input)
          targetCRC = CRC32 (getWord32LE (inputLength - 2 * crcLength) input)
          -- Parse body between magic and footer using ByteParser monad
          bodyBytes = ByteString.take (inputLength - overheadLength) (ByteString.drop magicLength input)
      case runByteParser parseBPSBody bodyBytes of
        Left parserError -> Left (ParseError LabelBPS parserError)
        Right body
          | unFileSize (bpsBodySourceSize body) < 0 ->
              Left (NegativeSize LabelBPS FieldSourceSize
                (ParsedSizeValue (unFileSize (bpsBodySourceSize body))))
          | unFileSize (bpsBodyTargetSize body) < 0 ->
              Left (NegativeSize LabelBPS FieldTargetSize
                (ParsedSizeValue (unFileSize (bpsBodyTargetSize body))))
          | otherwise ->
              Right (Parsed
                BPSPatch
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
                (bpsBodyWarnings body))

parseBPSBody :: ByteParser BPSBody
parseBPSBody = do
  rawSourceSize <- byuuVarint
  rawTargetSize <- byuuVarint
  let sourceSize = FileSize (fromIntegral rawSourceSize)
      targetSize = FileSize (fromIntegral rawTargetSize)
  metadataLength <- fromIntegral <$> byuuVarint
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
-- The only warning emitted here is 'NegativeZeroInBPS' (the non-canonical @0x81@ encoding of zero in a copy action's signed-delta varint).
-- Strictly private to 'Slap.BPS.Parse' —
-- the public surface of 'BPSBody' carries the same two pieces of information through 'bpsBodyActions' and 'bpsBodyWarnings'.
data BPSParsedActionStream = BPSParsedActionStream
  { parsedActionList     :: ![BPSAction]
  , parsedActionWarnings :: ![SlapAdvisory]
  }

-- | One decoded action plus the warnings its decoding emitted.
-- 'decodeOneAction' returns this so the per-arm logic for the four
-- BPS command codes — including the @0x81@ negative-zero detection
-- on 'SourceCopy' / 'TargetCopy' offset varints — lives in one
-- helper, leaving 'parseActions' as a thin tail-recursive walker
-- that just stitches results into its two reversed accumulators.
data BPSDecodedAction = BPSDecodedAction
  { bpsDecodedActionValue    :: !BPSAction
  , bpsDecodedActionWarnings :: ![SlapAdvisory]
  }

-- | Which kind of copy action 'decodeCopyAction' is decoding. The
-- two BPS copy commands have identical wire shapes (signed-delta
-- varint following the packed header) and differ only in which
-- buffer their copy reads from.
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
  let dataLength = Length (fromIntegral (shiftR packedCommandAndLength 2) + 1)
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
  let delta = Delta (fromIntegral (decodeSignedVarint offsetEncoded))
      action = case copyKind of
        CopyFromSource -> SourceCopy dataLength delta
        CopyFromTarget -> TargetCopy dataLength delta
  pure BPSDecodedAction
    { bpsDecodedActionValue    = action
    , bpsDecodedActionWarnings = [NegativeZeroInBPS | isNegativeZeroSignedVarint offsetEncoded]
    }
