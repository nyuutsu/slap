module Slap.DPS.Parse
  ( parseDPS
  , parseRecords
  , isDPS
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/DPS (format spec, from DPS patcher source)
-- Original C source: https://github.com/xperia64/android-rom-patcher/blob/master/jni/dpspatcher/dpspatcher.c
-- Author: Marc de Falco (Deufeufeu); deufeufeu.free.fr is dead.

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), DPSFormatVersion(..),
                        toDPSStability, toDPSFormatVersion,
                        dpsSourceSizeFromParsed,
                        dpsFieldWidth, dpsMinimumFileSize,
                        dpsVersionOffset, dpsStabilityOffset,
                        dpsCopyFromROMMode, dpsEnclosedDataMode,
                        dpsRecordHeaderSize, dpsCopyRecordSize)
import Slap.Status (SlapError(..), SlapAdvisory, Parsed(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runByteParser, getByte, getBytes, remaining)
import qualified Slap.ByteParser as ByteParser
import Slap.Measure (Length(..), offsetFromParsed,
                     RequiredLength(..), ActualLength(..),
                     RawFlagByte(..), byteLength)
import Slap.Text (EncodedText, EncodingName(..),
                  decodeTextLenient, decodeLossAdvisories)

import Data.Bits (shiftL, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Detection heuristic (no magic bytes)
----------------------------------------------------------------------------

-- | Heuristic detection: DPS files have version byte = 1 at
-- dpsVersionOffset, stability flag ∈ {0,1} at dpsStabilityOffset,
-- and records that parse cleanly to end of file.
isDPS :: ByteString -> Bool
isDPS input
  | ByteString.length input < dpsMinimumFileSize = False
  | ByteString.index input dpsVersionOffset /= 1 = False
  | ByteString.index input dpsStabilityOffset > 1 = False
  | otherwise = walkRecords dpsMinimumFileSize
  where
    inputLength = ByteString.length input
    -- Tentative record walk: each record starts with a mode byte, then
    -- mode 0 (CopyFromROM): outputOffset(4) + sourceOffset(4) + length(4)
    -- mode 1 (EnclosedData): outputOffset(4) + dataLength(4) + data(dataLength)
    -- Records must consume the remaining bytes exactly.
    walkRecords position
      | position == inputLength = True
      | position > inputLength  = False
      | otherwise =
          let modeByte = ByteString.index input position
          in if modeByte == dpsCopyFromROMMode
             then position + dpsCopyRecordSize <= inputLength
                  && walkRecords (position + dpsCopyRecordSize)
             else if modeByte == dpsEnclosedDataMode
             then let fixedSize = dpsRecordHeaderSize + 4  -- + dataLength field
                  in position + fixedSize <= inputLength
                     && let dataLength = word32LEAt (position + dpsRecordHeaderSize)
                        in walkRecords (position + fixedSize + dataLength)
             else False
    word32LEAt offset
      | offset + 4 > inputLength = inputLength  -- out of bounds → force walk failure
      | otherwise =
          let byte0 = fromIntegral (ByteString.index input offset) :: Int
              byte1 = fromIntegral (ByteString.index input (offset + 1)) `shiftL` 8
              byte2 = fromIntegral (ByteString.index input (offset + 2)) `shiftL` 16
              byte3 = fromIntegral (ByteString.index input (offset + 3)) `shiftL` 24
          in byte0 .|. byte1 .|. byte2 .|. byte3

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseDPS :: EncodingName -> PatchFileContents -> Either SlapError (Parsed DPSPatch)
parseDPS metadataEncoding (PatchFileContents input)
  | ByteString.length input < dpsMinimumFileSize = Left (InputTooShort LabelDPS (RequiredLength (Length dpsMinimumFileSize)) (ActualLength (byteLength input)))
  | Left versionError <- toDPSFormatVersion (ByteString.index input dpsVersionOffset)
    = Left versionError
  | otherwise = case runByteParser (parseDPSBody metadataEncoding) input of
      Left parserError                  -> Left (ParseError LabelDPS parserError)
      Right (Left slapError)            -> Left slapError
      Right (Right (patch, advisories)) -> Right (Parsed patch advisories)

-- | Decode one 64-byte metadata field under the chosen metadata
-- encoding. Lenient: substitution events surface as
-- 'FieldDecodedSubstituted' advisories tagged with the supplied
-- 'FieldName'.
parseMetadataField :: EncodingName -> FieldName -> ByteParser (EncodedText, [SlapAdvisory])
parseMetadataField metadataEncoding fieldName = do
  bytes <- getBytes (Length dpsFieldWidth)
  let (text, notices) = decodeTextLenient metadataEncoding bytes
  pure (text, decodeLossAdvisories LabelDPS fieldName notices)

parseDPSBody :: EncodingName -> ByteParser (Either SlapError (DPSPatch, [SlapAdvisory]))
parseDPSBody metadataEncoding = do
  (name,    nameAdvisories)    <- parseMetadataField metadataEncoding FieldPatchName
  (author,  authorAdvisories)  <- parseMetadataField metadataEncoding FieldAuthor
  (version, versionAdvisories) <- parseMetadataField metadataEncoding FieldVersion
  flagByte <- getByte
  case toDPSStability flagByte of
    Left errorMessage -> fail errorMessage
    Right stability -> do
      _ <- getByte  -- version byte (validated by parseDPS guard)
      originalSize  <- dpsSourceSizeFromParsed <$> ByteParser.word32LE
      recordsResult <- parseRecords
      pure $ case recordsResult of
        Left slapError -> Left slapError
        Right records  -> Right
          ( DPSPatch
              { dpsName          = name
              , dpsAuthor        = author
              , dpsVersion       = version
              , dpsStability     = stability
              , dpsFormatVersion = DPSVersion1
              , dpsOriginalSize  = originalSize
              , dpsRecords       = records
              }
          , nameAdvisories ++ authorAdvisories ++ versionAdvisories
          )

parseRecords :: ByteParser (Either SlapError [DPSRecord])
parseRecords = do
  available <- remaining
  if unLength available < dpsRecordHeaderSize then pure (Right [])
  else do
    mode <- getByte
    outputOffset <- offsetFromParsed <$> ByteParser.word32LE
    -- UniPatcher wiki swaps mode descriptions; chunk structures are correct.
    case mode of
      0 -> do  -- CopyFromROM: read offset + length from patch
        sourceOffset <- offsetFromParsed <$> ByteParser.word32LE
        copyLength   <- Length . fromIntegral <$> ByteParser.word32LE
        let record = DPSCopyFromROM outputOffset sourceOffset copyLength
        rest <- parseRecords
        pure (fmap (record :) rest)
      1 -> do  -- EnclosedData: read length + data from patch
        dataLength  <- fromIntegral <$> ByteParser.word32LE :: ByteParser Int
        payload  <- getBytes (Length dataLength)
        let record = DPSEnclosedData outputOffset payload
        rest <- parseRecords
        pure (fmap (record :) rest)
      unknownByte ->
        pure (Left (UnknownFlag LabelDPS FieldRecordMode (RawFlagByte unknownByte)))
