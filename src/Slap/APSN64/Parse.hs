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
                           APSN64Country(..),
                           toAPSPatchType, toAPSImageFormat,
                           toAPSRecordEncoding, toAPSN64Country,
                           apsN64MagicBytes, apsN64DescriptionWidth,
                           apsN64RecordHeaderSize)
import Slap.Status (SlapError(..), GetErrorMessage(..), SlapAdvisory(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, skip, atEnd, remaining, word32LE)
import Slap.Measure (Length(..), FileSize(..), Offset(..),
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     byteLength)

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

-- | What 'parseN64' produces from the inner Get walk: the decoded
-- patch plus walker-time warnings accumulated during the walk, in
-- wire order. Today only 'APSN64UnrecognizedCountry' is emitted
-- here; future parse-time observations (unrecognized image format,
-- unrecognized record encoding, record-level oddities) accumulate
-- through the same channel as APSN64's polish pass lands them.
data APSN64ParseWalk = APSN64ParseWalk
  { apsN64ParseWalkPatch    :: !APSN64Patch
  , apsN64ParseWalkWarnings :: ![SlapAdvisory]
  }

parseAPSN64 :: PatchFileContents -> Either SlapError (Parsed APSN64Patch)
parseAPSN64 (PatchFileContents input)
  | ByteString.length input < magicLength =
      Left (InputTooShort LabelAPSN64
             (RequiredLength (Length magicLength))
             (ActualLength (byteLength input)))
  | ByteString.take magicLength input /= apsN64MagicBytes =
      Left (BadMagic LabelAPSN64 (ActualMagic (ByteString.take magicLength input)))
  | otherwise =
      case runGet parseN64 input of
        Left errorMessage -> Left (ParseError LabelAPSN64 (GetErrorMessage errorMessage))
        Right walk ->
          Right (Parsed (apsN64ParseWalkPatch walk) (apsN64ParseWalkWarnings walk))
  where
    magicLength = ByteString.length apsN64MagicBytes

parseN64 :: Get APSN64ParseWalk
parseN64 = do
  skip (byteLength apsN64MagicBytes)  -- "APS10"
  patchTypeByte <- getByte
  case toAPSPatchType patchTypeByte of
    Left errorMessage -> fail errorMessage
    Right patchType -> do
      encodingMethod <- toAPSRecordEncoding <$> getByte
      description <- getBytes (Length apsN64DescriptionWidth)
      case patchType of
        APSSimple -> do
          destinationSize <- FileSize . fromIntegral <$> word32LE
          records <- parseN64Records
          let patch = APSN64Patch
                APSN64Header
                  { apsN64PatchType = patchType, apsN64Encoding = encodingMethod, apsN64Description = description
                  , apsN64ImageFormat = Nothing, apsN64CartId = Nothing
                  , apsN64Country = Nothing, apsN64Crc = Nothing, apsN64DestinationSize = destinationSize
                  }
                (Vector.fromList records)
          pure APSN64ParseWalk
            { apsN64ParseWalkPatch    = patch
            , apsN64ParseWalkWarnings = []
            }
        APSN64Specific -> do
          imageFormat  <- toAPSImageFormat <$> getByte
          cartId  <- N64CartId <$> getBytes (Length 2)
          countryByte <- getByte
          let parsedCountry   = toAPSN64Country countryByte
              countryWarnings = case parsedCountry of
                APSN64CountryUnrecognized byte -> [APSN64UnrecognizedCountry byte]
                _                              -> []
          crcBytes  <- N64ChecksumPair <$> getBytes (Length 8)
          skip (Length 5)  -- padding (bytes 69-73)
          destinationSize <- FileSize . fromIntegral <$> word32LE
          records <- parseN64Records
          let patch = APSN64Patch
                APSN64Header
                  { apsN64PatchType = patchType, apsN64Encoding = encodingMethod, apsN64Description = description
                  , apsN64ImageFormat = Just imageFormat, apsN64CartId = Just cartId
                  , apsN64Country = Just parsedCountry, apsN64Crc = Just crcBytes, apsN64DestinationSize = destinationSize
                  }
                (Vector.fromList records)
          pure APSN64ParseWalk
            { apsN64ParseWalkPatch    = patch
            , apsN64ParseWalkWarnings = countryWarnings
            }

parseN64Records :: Get [APSN64Record]
parseN64Records = walkRecords []
  where
    walkRecords :: [APSN64Record] -> Get [APSN64Record]
    walkRecords accumulatedReversed = do
      done <- atEnd
      if done then pure (reverse accumulatedReversed)
      else do
        remainingLength <- remaining
        if remainingLength < apsN64RecordHeaderSize
          then pure (reverse accumulatedReversed)
          else do
            recordOffset <- Offset . fromIntegral <$> word32LE
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
