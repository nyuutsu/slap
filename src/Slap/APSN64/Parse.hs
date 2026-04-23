{-# LANGUAGE OverloadedStrings #-}

module Slap.APSN64.Parse
  ( parseAPSN64
  , parseN64
  , parseN64Records
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/APS-(N64) (Blackbag spec, 1998)
-- Secondary: RomPatcher.js modules/RomPatcher.format.aps_n64.js

import Slap.APSN64.Types (APSN64Patch(..), APSN64Record(..), APSN64Header(..),
                           APSPatchType(..), toAPSPatchType, toAPSImageFormat,
                           toAPSRecordEncoding, apsN64MagicBytes, apsN64DescriptionWidth)
import Slap.Error (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, skip, atEnd, remaining, word32LE)
import Slap.Measure (Length(..), FileSize(..), Offset(..),
                     RequiredLength(..), ActualLength(..), ActualMagic(..))

import qualified Data.ByteString as ByteString

parseAPSN64 :: PatchFileContents -> Either SlapError (Parsed APSN64Patch)
parseAPSN64 (PatchFileContents input)
  | ByteString.length input < 5 =
      Left (InputTooShort LabelAPSN64 (RequiredLength (Length 5)) (ActualLength (Length (ByteString.length input))))
  | ByteString.take 5 input /= apsN64MagicBytes =
      Left (BadMagic LabelAPSN64 (ActualMagic (ByteString.take 5 input)))
  | otherwise =
      case runGet parseN64 input of
        Left errorMessage -> Left (ParseError LabelAPSN64 errorMessage)
        Right patch -> Right (Parsed patch [])

parseN64 :: Get APSN64Patch
parseN64 = do
  skip (Length 5)  -- "APS10"
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
          pure $ APSN64Patch
            APSN64Header
              { apsN64PatchType = patchType, apsN64Encoding = encodingMethod, apsN64Description = description
              , apsN64ImageFormat = Nothing, apsN64CartId = Nothing
              , apsN64Country = Nothing, apsN64Crc = Nothing, apsN64DestinationSize = destinationSize
              }
            records
        APSN64Specific -> do
          imageFormat  <- toAPSImageFormat <$> getByte
          cartId  <- getBytes (Length 2)
          country <- getByte
          crcBytes  <- getBytes (Length 8)
          skip (Length 5)  -- padding (bytes 69-73)
          destinationSize <- FileSize . fromIntegral <$> word32LE
          records <- parseN64Records
          pure $ APSN64Patch
            APSN64Header
              { apsN64PatchType = patchType, apsN64Encoding = encodingMethod, apsN64Description = description
              , apsN64ImageFormat = Just imageFormat, apsN64CartId = Just cartId
              , apsN64Country = Just country, apsN64Crc = Just crcBytes, apsN64DestinationSize = destinationSize
              }
            records

parseN64Records :: Get [APSN64Record]
parseN64Records = do
  done <- atEnd
  if done then pure []
  else do
    remainingLength <- remaining
    if unLength remainingLength < 5 then pure []
    else do
      offset <- Offset . fromIntegral <$> word32LE
      dataLength <- getByte
      if dataLength == 0
        then do  -- RLE record
          value <- getByte
          count <- getByte
          rest <- parseN64Records
          pure (APSN64RLE offset value count : rest)
        else do  -- Normal record
          payload <- getBytes (Length (fromIntegral dataLength))
          rest <- parseN64Records
          pure (APSN64Normal offset payload : rest)
