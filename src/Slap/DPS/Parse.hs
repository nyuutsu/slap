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
import Slap.Status (SlapError(..), SlapAdvisory, Parsed(..), ByteParserError(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (byteAtOffset)
import Slap.ByteParser (ByteParser, runFormatParser, flattenParse, getByte, getBytes, remaining,
                        throwByteParserError)
import qualified Slap.ByteParser as ByteParser
import Slap.Measure (Length(..), offsetFromParsed,
                     RequiredLength(..), RemainingLength(..), ActualLength(..),
                     ActionIndex, firstAction, nextAction,
                     RawFlagByte(..), byteLength)
import Slap.Text (EncodedText, EncodingName(..), decodeFixedWidthTextField)

import Data.Bits (shiftL, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Detection heuristic (no magic bytes)
----------------------------------------------------------------------------

isDPS :: ByteString -> Bool
isDPS input
  | byteLength input < dpsMinimumFileSize = False
  | byteAtOffset dpsVersionOffset input /= 1 = False
  | byteAtOffset dpsStabilityOffset input > 1 = False
  | otherwise = recordsConsumeToEnd recordStreamStart
  where
    inputLength = ByteString.length input
    -- The walk below is an Int cursor over 'ByteString.index'; it steps out of measure space once, here at its seed.
    recordStreamStart = fromIntegral (unLength dpsMinimumFileSize) :: Int
    -- Tentative record walk: each record starts with a mode byte, then
    -- mode 0 (CopyFromROM): outputOffset(4) + sourceOffset(4) + length(4)
    -- mode 1 (EnclosedData): outputOffset(4) + dataLength(4) + data(dataLength)
    -- Records must consume the remaining bytes exactly.
    recordsConsumeToEnd position
      | position == inputLength = True
      | position > inputLength  = False
      | otherwise =
          let modeByte = ByteString.index input position
          in if modeByte == dpsCopyFromROMMode
             then position + dpsCopyRecordSize <= inputLength
                  && recordsConsumeToEnd (position + dpsCopyRecordSize)
             else if modeByte == dpsEnclosedDataMode
             then let fixedSize = dpsRecordHeaderSize + 4  -- + dataLength field
                  in position + fixedSize <= inputLength
                     && let dataLength = readWord32LEAt (position + dpsRecordHeaderSize)
                        in recordsConsumeToEnd (position + fixedSize + dataLength)
             else False
    readWord32LEAt offset
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
  | byteLength input < dpsMinimumFileSize = Left (InputTooShort LabelDPS (RequiredLength dpsMinimumFileSize) (ActualLength (byteLength input)))
  | Left versionError <- toDPSFormatVersion (byteAtOffset dpsVersionOffset input)
    = Left versionError
  | otherwise = do
      (patch, advisories) <- flattenParse (runFormatParser LabelDPS (parseDPSBody metadataEncoding) input)
      Right (Parsed patch advisories)

-- | Decode one 64-byte metadata field under the chosen metadata
-- encoding. Lenient: substitution events surface as
-- 'FieldDecodedSubstituted' advisories tagged with the supplied
-- 'FieldName'.
parseMetadataField :: EncodingName -> FieldName -> ByteParser (EncodedText, [SlapAdvisory])
parseMetadataField metadataEncoding fieldName = do
  bytes <- getBytes dpsFieldWidth
  pure (decodeFixedWidthTextField metadataEncoding LabelDPS fieldName bytes)

parseDPSBody :: EncodingName -> ByteParser (Either SlapError (DPSPatch, [SlapAdvisory]))
parseDPSBody metadataEncoding = do
  (name,    nameAdvisories)    <- parseMetadataField metadataEncoding FieldPatchName
  (author,  authorAdvisories)  <- parseMetadataField metadataEncoding FieldAuthor
  (version, versionAdvisories) <- parseMetadataField metadataEncoding FieldVersion
  flagByte <- getByte
  case toDPSStability flagByte of
    Nothing        -> pure (Left (UnknownFlag LabelDPS FieldStability (RawFlagByte flagByte)))
    Just stability -> do
      _ <- getByte  -- version byte (validated by parseDPS guard)
      originalSize  <- dpsSourceSizeFromParsed <$> ByteParser.word32LE
      recordsResult <- parseRecords firstAction
      pure $ fmap
        (\records ->
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
          ))
        recordsResult

parseRecords :: ActionIndex -> ByteParser (Either SlapError [DPSRecord])
parseRecords recordIndex = do
  available <- remaining
  if unLength available == 0 then pure (Right [])
  else if unLength available < fromIntegral dpsRecordHeaderSize then
    -- Bytes remain but too few to begin a record (mode byte + 4-byte
    -- output offset). DPS records run to EOF with nothing after the
    -- last one, so a sub-header tail is a truncated record, not a clean
    -- end. Detection requires exact consumption (isDPS); the parser
    -- agrees rather than silently dropping the tail.
    throwByteParserError (ByteParserTruncatedRecord recordIndex
      (RequiredLength (Length (fromIntegral dpsRecordHeaderSize)))
      (RemainingLength available))
  else do
    mode <- getByte
    outputOffset <- offsetFromParsed <$> ByteParser.word32LE
    -- UniPatcher wiki swaps mode descriptions; chunk structures are correct.
    case mode of
      m | m == dpsCopyFromROMMode -> do
            sourceOffset <- offsetFromParsed <$> ByteParser.word32LE
            copyLength   <- Length . fromIntegral <$> ByteParser.word32LE
            let record = DPSCopyFromROM outputOffset sourceOffset copyLength
            rest <- parseRecords (nextAction recordIndex)
            pure (fmap (record :) rest)
        | m == dpsEnclosedDataMode -> do
            dataLength  <- fromIntegral <$> ByteParser.word32LE :: ByteParser Int
            payload  <- getBytes (Length (fromIntegral dataLength))
            let record = DPSEnclosedData outputOffset payload
            rest <- parseRecords (nextAction recordIndex)
            pure (fmap (record :) rest)
      unknownByte ->
        pure (Left (UnknownFlag LabelDPS FieldRecordMode (RawFlagByte unknownByte)))
