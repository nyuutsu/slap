{-# LANGUAGE OverloadedStrings #-}

module Slap.APSN64.Parse
  ( parseAPSN64
  , parseN64
  , parseN64Records
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/APS-(N64) (Blackbag spec, 1998)
-- Secondary: RomPatcher.js modules/RomPatcher.format.aps_n64.js

import Slap.APSN64.Types (APSN64Patch(..), APSN64Record(..), APSN64Header(..),
                           APSPatchType(..), N64CartId(..), N64ChecksumPair(..),
                           toAPSPatchType, toAPSEncodingMethod, toAPSImageFormat,
                           toAPSN64Country,
                           apsN64MagicBytes, apsN64DescriptionWidth,
                           apsN64RecordHeaderSize,
                           apsN64DestinationSizeFromParsed)
import Slap.Status (SlapError(..), SlapAdvisory(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, getByte, getBytes, skip, remaining, word32LE)
import Slap.Measure (Length(..), offsetFromParsed,
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     byteLength)
import Slap.Text (EncodingName(..), decodeFixedWidthTextField)

import Data.Bifunctor (first)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

-- | What 'parseN64' produces from the inner ByteParser walk: the decoded
-- patch plus walker-time advisories accumulated during the walk, in wire
-- order. Today only description-decode advisories are emitted here.
data APSN64ParseWalk = APSN64ParseWalk
  { apsN64ParseWalkPatch    :: !APSN64Patch
  , apsN64ParseWalkWarnings :: ![SlapAdvisory]
  }

parseAPSN64 :: EncodingName -> PatchFileContents -> Either SlapError (Parsed APSN64Patch)
parseAPSN64 metadataEncoding (PatchFileContents input)
  | ByteString.length input < magicLength =
      Left (InputTooShort LabelAPSN64
             (RequiredLength (Length (fromIntegral magicLength)))
             (ActualLength (byteLength input)))
  | ByteString.take magicLength input /= apsN64MagicBytes =
      Left (BadMagic LabelAPSN64 (ActualMagic (ByteString.take magicLength input)))
  | ByteString.length input < magicLength + 2 =
      Left (InputTooShort LabelAPSN64
             (RequiredLength (Length (fromIntegral (magicLength + 2))))
             (ActualLength (byteLength input)))
  | otherwise = do
      patchType <- first MalformedAPSN64Header (toAPSPatchType (ByteString.index input magicLength))
      first MalformedAPSN64Header (toAPSEncodingMethod (ByteString.index input (magicLength + 1)))
      walk <- runFormatParser LabelAPSN64 (parseN64 metadataEncoding patchType) input
      Right (Parsed (apsN64ParseWalkPatch walk) (apsN64ParseWalkWarnings walk))
  where
    magicLength = ByteString.length apsN64MagicBytes

parseN64 :: EncodingName -> APSPatchType -> ByteParser APSN64ParseWalk
parseN64 metadataEncoding patchType = do
  skip (byteLength apsN64MagicBytes)  -- "APS10"
  skip (Length 1)                     -- patch-type byte (pre-validated)
  skip (Length 1)                     -- encoding byte (pre-validated == 0)
  descriptionBytes  <- getBytes apsN64DescriptionWidth
  let (description, descriptionAdvisories) =
        decodeFixedWidthTextField metadataEncoding LabelAPSN64 FieldDescription descriptionBytes
  case patchType of
    APSSimple -> do
      destinationSize <- apsN64DestinationSizeFromParsed <$> word32LE
      recordWalk      <- parseN64Records
      let patch = APSN64Patch
            APSN64Header
              { apsN64PatchType = patchType, apsN64Description = description
              , apsN64ImageFormat = Nothing, apsN64CartId = Nothing
              , apsN64Country = Nothing, apsN64Crc = Nothing, apsN64DestinationSize = destinationSize
              }
            (Vector.fromList (apsN64WalkRecords recordWalk))
      pure APSN64ParseWalk
        { apsN64ParseWalkPatch    = patch
        , apsN64ParseWalkWarnings = descriptionAdvisories ++ apsN64WalkAdvisories recordWalk
        }
    APSN64Specific -> do
      imageFormat <- toAPSImageFormat <$> getByte
      cartId      <- N64CartId <$> getBytes (Length 2)
      countryByte <- getByte
      let parsedCountry = toAPSN64Country countryByte
      crcBytes        <- N64ChecksumPair <$> getBytes (Length 8)
      skip (Length 5)  -- padding (bytes 69-73)
      destinationSize <- apsN64DestinationSizeFromParsed <$> word32LE
      recordWalk      <- parseN64Records
      let patch = APSN64Patch
            APSN64Header
              { apsN64PatchType = patchType, apsN64Description = description
              , apsN64ImageFormat = Just imageFormat, apsN64CartId = Just cartId
              , apsN64Country = Just parsedCountry, apsN64Crc = Just crcBytes, apsN64DestinationSize = destinationSize
              }
            (Vector.fromList (apsN64WalkRecords recordWalk))
      pure APSN64ParseWalk
        { apsN64ParseWalkPatch    = patch
        , apsN64ParseWalkWarnings = descriptionAdvisories ++ apsN64WalkAdvisories recordWalk
        }

-- | What the record walk finds at the cursor: input spent exactly on
-- a record boundary, a fragment too short to begin another record,
-- or a record ahead.
data APSN64StreamHead
  = StreamSpent
  | TrailingFragment !Length
  | RecordAhead

-- | The record walk's product: the records in wire order, plus the
-- advisories the walk surfaced — today only 'APSN64TrailingFragment'.
data APSN64RecordWalk = APSN64RecordWalk
  { apsN64WalkRecords    :: ![APSN64Record]
  , apsN64WalkAdvisories :: ![SlapAdvisory]
  }

-- | Walk records to end of input. A trailing fragment — fewer bytes
-- than a record header where a record would begin — ends the walk;
-- the fragment is consumed and surfaced as a note.
parseN64Records :: ByteParser APSN64RecordWalk
parseN64Records = walkRecords []
  where
    walkRecords :: [APSN64Record] -> ByteParser APSN64RecordWalk
    walkRecords accumulatedReversed = do
      streamHead <- classifyStreamHead <$> remaining
      case streamHead of
        StreamSpent ->
          pure (APSN64RecordWalk (reverse accumulatedReversed) [])
        TrailingFragment fragmentLength -> do
          skip fragmentLength
          pure (APSN64RecordWalk (reverse accumulatedReversed)
                  [APSN64TrailingFragment fragmentLength])
        RecordAhead -> do
          recordOffset <- offsetFromParsed <$> word32LE
          dataLength   <- getByte
          decodedRecord <- if dataLength == 0
            then do  -- RLE record
              fillValue <- getByte
              fillCount <- getByte
              pure (APSN64RLE recordOffset fillValue fillCount)
            else do  -- Normal record
              recordPayload <- getBytes (Length (fromIntegral dataLength))
              pure (APSN64Normal recordOffset recordPayload)
          walkRecords (decodedRecord : accumulatedReversed)

    classifyStreamHead :: Length -> APSN64StreamHead
    classifyStreamHead remainingLength
      | remainingLength == Length 0             = StreamSpent
      | remainingLength < apsN64RecordHeaderSize = TrailingFragment remainingLength
      | otherwise                                = RecordAhead
