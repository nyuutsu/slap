{-# LANGUAGE OverloadedStrings #-}

module Slap.PPF.Parse (parsePatch) where

-- Canonical references:
--   PPF1: Icarus/PPF-Studio (public spec)
--   PPF2: Icarus/PPF-Studio (public spec)
--   PPF3: Icarus/PPF-Studio (public spec)
--   PPF4: Pyriel's patcher.lua / ppfmaker.cpp (source code of the only tools that produce/consume it)
-- Secondary: RomPatcher.js modules/RomPatcher.format.ppf.js

import Slap.PPF.Types (PPFPatch(..), PPFRecord(..), PPFRecordCommand(..),
                        PPFVersion(..), PPFValidation(..), PPFFileId(..), PPFImageType(..),
                        ppfPreambleLength, ppfDescriptionLength,
                        ppf2HeaderLength, ppf3MinHeaderLength,
                        ppf4PostDescriptionLength, validationSize,
                        fileIdMarkerLength, fileIdFooterLength,
                        ppfVersionLabel)
import Slap.Binary (getWord16LE, getWord32LE)
import Slap.Error (SlapError(..), FieldName(..))
import Slap.Format (padHex)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, skip, remaining, word32LE, int64LE)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), FoundVersion(..),
                     EncodingMethodByte(..), RawFlagByte(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)

-- | Parse a PPF patch file from raw bytes.
parsePatch :: ByteString -> Either SlapError PPFPatch
parsePatch input = do
  version <- detectVersion input
  checkEncoding version input
  case version of
    PPF1 -> parsePPF1 input
    PPF2 -> parsePPF2 input
    PPF3 -> parsePPF3 input
    PPF4 -> parsePPF4 input

-- | Wrap a Get error string into a SlapError.
wrapError :: FormatLabel -> Either String a -> Either SlapError a
wrapError label = either (Left . ParseError label) Right

-- Version detection: bytes 0-3 as ASCII "PPF1" .. "PPF4".
detectVersion :: ByteString -> Either SlapError PPFVersion
detectVersion input
  | ByteString.length input < 6    = Left (InputTooShort LabelPPF1 (RequiredLength (Length 6)) (ActualLength (Length (ByteString.length input))))
  | magic == "PPF1"        = Right PPF1
  | magic == "PPF2"        = Right PPF2
  | magic == "PPF3"        = Right PPF3
  | magic == "PPF4"        = Right PPF4
  | ByteString.take 3 input == "PPF" = Left (BadVersion LabelPPF1 (FoundVersion (ByteString.index input 3)))
  | otherwise              = Left (BadMagic LabelPPF1 (ActualMagic (ByteString.take 5 input)))
  where magic = ByteString.take 4 input

-- Byte 5: encoding method.  PPF1 = 0x00, PPF2 = 0x01, PPF3 = 0x02.
-- PPF4 is undocumented — accept any value.
checkEncoding :: PPFVersion -> ByteString -> Either SlapError ()
checkEncoding PPF4 _ = Right ()
checkEncoding version input
  | encoding == expected = Right ()
  | otherwise = Left (UnsupportedEncodingMethod (ppfVersionLabel version) (EncodingMethodByte encoding))
  where
    encoding = ByteString.index input 5
    expected = case version of
      PPF1 -> 0x00 :: Word8
      PPF2 -> 0x01
      PPF3 -> 0x02

-- PPF1: 56-byte header, then records with 4-byte offsets.
parsePPF1 :: ByteString -> Either SlapError PPFPatch
parsePPF1 input = wrapError LabelPPF1 $ runGet parsePPF1Body input
  where
    parsePPF1Body :: Get PPFPatch
    parsePPF1Body = do
      skip ppfPreambleLength
      description <- getBytes ppfDescriptionLength
      records <- parseRecords32 LabelPPF1 0
      pure PPFPatch
        { ppfVersion     = PPF1
        , ppfDescription = description
        , ppfFileSize    = Nothing
        , ppfValidation  = Nothing
        , ppfHasUndo     = False
        , ppfImageType   = Nothing
        , ppfRecords     = records
        , ppfFileId      = Nothing
        }

-- PPF2: 1084-byte header, then records with 4-byte offsets, optional File_ID.diz.
parsePPF2 :: ByteString -> Either SlapError PPFPatch
parsePPF2 input = do
  let fileId     = detectFileId getWord32LE 4 input
      recordBody = stripFileId 4 fileId (ByteString.drop (unLength ppf2HeaderLength) input)
  (description, fileSize, validationBlock) <-
    wrapError LabelPPF2 $ runGet parsePPF2Header input
  records <- wrapError LabelPPF2 $ runGet (parseRecords32 LabelPPF2 0) recordBody
  Right PPFPatch
    { ppfVersion     = PPF2
    , ppfDescription = description
    , ppfFileSize    = Just fileSize
    , ppfValidation  = Just (PPFValidation BIN validationBlock)
    , ppfHasUndo     = False
    , ppfImageType   = Nothing
    , ppfRecords     = records
    , ppfFileId      = fileId
    }
  where
    parsePPF2Header :: Get (ByteString, FileSize, ByteString)
    parsePPF2Header = do
      skip ppfPreambleLength
      description <- getBytes ppfDescriptionLength
      fileSize <- FileSize . fromIntegral <$> word32LE
      validationBlock <- getBytes validationSize
      pure (description, fileSize, validationBlock)

-- | Intermediate result of parsing the PPF3 fixed header fields.
data PPF3ParsedHeader = PPF3ParsedHeader
  { ppf3Description     :: !ByteString
  , ppf3ImageTypeByte   :: !Word8
  , ppf3HasBlockCheck   :: !Bool
  , ppf3HasUndo         :: !Bool
  , ppf3ValidationBlock :: !(Maybe ByteString)
  }

-- PPF3: 60 or 1084-byte header, then records with 8-byte offsets, optional undo.
parsePPF3 :: ByteString -> Either SlapError PPFPatch
parsePPF3 input = do
  header <- wrapError LabelPPF3 $ runGet parsePPF3Header input
  imageType <- case ppf3ImageTypeByte header of
    0x00 -> Right BIN
    0x01 -> Right GI
    byte -> Left (UnknownFlag LabelPPF3 FieldImageType (RawFlagByte byte))
  let validation = PPFValidation imageType <$> ppf3ValidationBlock header
      headerLength = if ppf3HasBlockCheck header then ppf3MinHeaderLength <> validationSize else ppf3MinHeaderLength
      fileId     = detectFileId getWord16LE 2 input
      recordBody = stripFileId 2 fileId (ByteString.drop (unLength headerLength) input)
  records <- wrapError LabelPPF3 $ runGet (parseRecords64 LabelPPF3 (ppf3HasUndo header) 0) recordBody
  Right PPFPatch
    { ppfVersion     = PPF3
    , ppfDescription = ppf3Description header
    , ppfFileSize    = Nothing
    , ppfValidation  = validation
    , ppfHasUndo     = ppf3HasUndo header
    , ppfImageType   = Just imageType
    , ppfRecords     = records
    , ppfFileId      = fileId
    }
  where
    parsePPF3Header :: Get PPF3ParsedHeader
    parsePPF3Header = do
      skip ppfPreambleLength
      description <- getBytes ppfDescriptionLength
      imageTypeByte <- getByte
      hasBlockByte <- getByte
      hasUndoByte <- getByte
      skip (Length 1)
      validationBlock <- if hasBlockByte /= 0
        then Just <$> getBytes validationSize
        else pure Nothing
      pure PPF3ParsedHeader
        { ppf3Description     = description
        , ppf3ImageTypeByte   = imageTypeByte
        , ppf3HasBlockCheck   = hasBlockByte /= 0
        , ppf3HasUndo         = hasUndoByte /= 0
        , ppf3ValidationBlock = validationBlock
        }

-- Pyriel's internal format (magic "PPF4"): 60-byte header, records with command byte +
-- 4-byte offsets.  Reverse-engineered from the Suikoden I/II bug fix patchers; not a
-- published spec — only ever generated and consumed within those patchers' Lua runtime.
parsePPF4 :: ByteString -> Either SlapError PPFPatch
parsePPF4 input = wrapError LabelPPF4 $ runGet parsePPF4Body input
  where
    parsePPF4Body :: Get PPFPatch
    parsePPF4Body = do
      skip ppfPreambleLength
      description <- getBytes ppfDescriptionLength
      skip ppf4PostDescriptionLength
      records <- parseRecords4 LabelPPF4 0
      pure PPFPatch
        { ppfVersion     = PPF4
        , ppfDescription = description
        , ppfFileSize    = Nothing
        , ppfValidation  = Nothing
        , ppfHasUndo     = False
        , ppfImageType   = Nothing
        , ppfRecords     = records
        , ppfFileId      = Nothing
        }

----------------------------------------------------------------------------
-- Record parsers (Get actions)
----------------------------------------------------------------------------

-- Parse PPF1/PPF2 records (4-byte offset, 1-byte count, N bytes data).
parseRecords32 :: FormatLabel -> Int -> Get [PPFRecord]
parseRecords32 label recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 5 then pure []
  else do
    recordOffset <- Offset . fromIntegral <$> word32LE
    count <- fromIntegral <$> getByte
    remainingAfterHeader <- remaining
    if unLength remainingAfterHeader < count
      then fail (truncatedMessage recordIndex (5 + count) (unLength remainingBytes))
      else do
        payload <- getBytes (Length count)
        rest <- parseRecords32 label (recordIndex + 1)
        pure (PPFRecord recordOffset payload Nothing Replace : rest)

-- Parse PPF3 records (8-byte offset, 1-byte count, N bytes data, optional undo).
parseRecords64 :: FormatLabel -> Bool -> Int -> Get [PPFRecord]
parseRecords64 label hasUndo recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 9 then pure []
  else do
    recordOffset <- Offset . fromIntegral <$> int64LE
    count <- fromIntegral <$> getByte
    let need = 9 + count + if hasUndo then count else 0
    if need > unLength remainingBytes
      then fail (truncatedMessage recordIndex need (unLength remainingBytes))
      else do
        payload <- getBytes (Length count)
        undoData <- if hasUndo
                    then Just <$> getBytes (Length count)
                    else pure Nothing
        rest <- parseRecords64 label hasUndo (recordIndex + 1)
        pure (PPFRecord recordOffset payload undoData Replace : rest)

-- Parse PPF4 records (1-byte cmd, 4-byte offset, 1-byte count, N bytes data).
parseRecords4 :: FormatLabel -> Int -> Get [PPFRecord]
parseRecords4 label recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 6 then pure []
  else do
    commandByte <- getByte
    command <- case commandByte of
      0 -> pure Replace
      1 -> pure Append
      _ -> fail ("record " ++ show recordIndex
                ++ " has unknown command byte: 0x" ++ padHex 2 commandByte)
    recordOffset <- Offset . fromIntegral <$> word32LE
    count <- fromIntegral <$> getByte
    remainingAfterHeader <- remaining
    if unLength remainingAfterHeader < count
      then fail (truncatedMessage recordIndex (6 + count) (unLength remainingBytes))
      else do
        payload <- getBytes (Length count)
        rest <- parseRecords4 label (recordIndex + 1)
        pure (PPFRecord recordOffset payload Nothing command : rest)

-- Format a truncated-record error message.
truncatedMessage :: Int -> Int -> Int -> String
truncatedMessage recordIndex needed available =
  "record " ++ show recordIndex
  ++ " truncated (need " ++ show needed ++ " bytes, " ++ show available ++ " available)"

----------------------------------------------------------------------------
-- File_ID.diz detection (operates on the full input ByteString)
----------------------------------------------------------------------------

-- File_ID.diz detection, parameterised by length-field reader and width.
detectFileId :: (Integral a) => (Int -> ByteString -> a) -> Int -> ByteString -> Maybe PPFFileId
detectFileId readLength lengthSize input
  | ByteString.length input < 4 + lengthSize = Nothing
  | ByteString.take 4 (ByteString.drop (ByteString.length input - 4 - lengthSize) input) == ".DIZ" =
      let idLength    = fromIntegral (readLength (ByteString.length input - lengthSize) input)
          trailerSize = unLength fileIdMarkerLength + idLength + unLength fileIdFooterLength + lengthSize
      in Just (PPFFileId (ByteString.take idLength (ByteString.drop (ByteString.length input - trailerSize + unLength fileIdMarkerLength) input)))
  | otherwise = Nothing

-- Strip File_ID.diz trailer bytes from the record body.
stripFileId :: Int -> Maybe PPFFileId -> ByteString -> ByteString
stripFileId _ Nothing body = body
stripFileId lengthSize (Just (PPFFileId content)) body =
  ByteString.take (ByteString.length body - unLength fileIdMarkerLength - ByteString.length content - unLength fileIdFooterLength - lengthSize) body
