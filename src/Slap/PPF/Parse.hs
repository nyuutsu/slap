{-# LANGUAGE OverloadedStrings #-}

module Slap.PPF.Parse (parsePatch) where

-- Canonical reference: reverse-engineered from Icarus/PPF-Studio; no formal spec
-- Secondary: RomPatcher.js modules/RomPatcher.format.ppf.js

import Slap.PPF.Types
import Slap.Binary (getWord16LE, getWord32LE)
import Slap.Error (SlapError(..), FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, skip, remaining, word32LE, int64LE)
import Slap.Measure (Offset(..), Length(..), FileSize(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)

-- | Parse a PPF patch file from raw bytes.
parsePatch :: ByteString -> Either SlapError Patch
parsePatch input = do
  version <- detectVersion input
  checkEncoding version input
  case version of
    PPF1 -> parsePPF1 input
    PPF2 -> parsePPF2 input
    PPF3 -> parsePPF3 input
    PPF4 -> parsePPF4 input

-- | Map a PPF version to its format label.
versionLabel :: Version -> FormatLabel
versionLabel PPF1 = LabelPPF1
versionLabel PPF2 = LabelPPF2
versionLabel PPF3 = LabelPPF3
versionLabel PPF4 = LabelPPF4

-- | Wrap a Get error string into a SlapError.
wrapError :: FormatLabel -> Either String a -> Either SlapError a
wrapError label = either (Left . ParseError label) Right

-- Version detection: bytes 0-3 as ASCII "PPF1" .. "PPF4".
detectVersion :: ByteString -> Either SlapError Version
detectVersion input
  | ByteString.length input < 6    = Left (InputTooShort LabelPPF1 (Length 6) (Length (ByteString.length input)))
  | magic == "PPF1"        = Right PPF1
  | magic == "PPF2"        = Right PPF2
  | magic == "PPF3"        = Right PPF3
  | magic == "PPF4"        = Right PPF4
  | ByteString.take 3 input == "PPF" = Left (BadVersion LabelPPF1 (ByteString.index input 3))
  | otherwise              = Left (BadMagic LabelPPF1 (ByteString.take 5 input))
  where magic = ByteString.take 4 input

-- Byte 5: encoding method.  PPF1 = 0x00, PPF2 = 0x01, PPF3 = 0x02.
-- PPF4 is undocumented — accept any value.
checkEncoding :: Version -> ByteString -> Either SlapError ()
checkEncoding PPF4 _ = Right ()
checkEncoding version input
  | encoding == expected = Right ()
  | otherwise = Left (UnsupportedEncodingMethod (versionLabel version) encoding)
  where
    encoding = ByteString.index input 5
    expected = case version of
      PPF1 -> 0x00 :: Word8
      PPF2 -> 0x01
      PPF3 -> 0x02

-- PPF1: 56-byte header, then records with 4-byte offsets.
parsePPF1 :: ByteString -> Either SlapError Patch
parsePPF1 input = wrapError LabelPPF1 $ runGet parsePPF1Body input
  where
    parsePPF1Body :: Get Patch
    parsePPF1Body = do
      skip (Length ppfDescriptionOffset)
      description <- getBytes (Length ppfDescriptionWidth)
      records <- parseRecords32 LabelPPF1 0
      pure Patch
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
parsePPF2 :: ByteString -> Either SlapError Patch
parsePPF2 input = do
  let fileId     = detectFileId getWord32LE 4 input
      recordBody = stripFileId 4 fileId (ByteString.drop ppf2HeaderSize input)
  (description, fileSize, validationBlock) <-
    wrapError LabelPPF2 $ runGet parsePPF2Header input
  records <- wrapError LabelPPF2 $ runGet (parseRecords32 LabelPPF2 0) recordBody
  Right Patch
    { ppfVersion     = PPF2
    , ppfDescription = description
    , ppfFileSize    = Just fileSize
    , ppfValidation  = Just (Validation BIN validationBlock)
    , ppfHasUndo     = False
    , ppfImageType   = Nothing
    , ppfRecords     = records
    , ppfFileId      = fileId
    }
  where
    parsePPF2Header :: Get (ByteString, FileSize, ByteString)
    parsePPF2Header = do
      skip (Length ppfDescriptionOffset)
      description <- getBytes (Length ppfDescriptionWidth)
      fileSize <- FileSize . fromIntegral <$> word32LE
      validationBlock <- getBytes validationSize
      pure (description, fileSize, validationBlock)

-- PPF3: 60 or 1084-byte header, then records with 8-byte offsets, optional undo.
parsePPF3 :: ByteString -> Either SlapError Patch
parsePPF3 input = do
  (description, imageTypeByte, hasBlock, hasUndo, validationBlock) <-
    wrapError LabelPPF3 $ runGet parsePPF3Header input
  imageType <- case imageTypeByte of
    0x00 -> Right BIN
    0x01 -> Right GI
    byte -> Left (UnknownFlag LabelPPF3 FieldImageType byte)
  let validation = Validation imageType <$> validationBlock
      headerSize = if hasBlock then ppf3MinHeaderSize + unLength validationSize else ppf3MinHeaderSize
      fileId     = detectFileId getWord16LE 2 input
      recordBody = stripFileId 2 fileId (ByteString.drop headerSize input)
  records <- wrapError LabelPPF3 $ runGet (parseRecords64 LabelPPF3 hasUndo 0) recordBody
  Right Patch
    { ppfVersion     = PPF3
    , ppfDescription = description
    , ppfFileSize    = Nothing
    , ppfValidation  = validation
    , ppfHasUndo     = hasUndo
    , ppfImageType   = Just imageType
    , ppfRecords     = records
    , ppfFileId      = fileId
    }
  where
    parsePPF3Header :: Get (ByteString, Word8, Bool, Bool, Maybe ByteString)
    parsePPF3Header = do
      skip (Length ppfDescriptionOffset)
      description <- getBytes (Length ppfDescriptionWidth)
      imageTypeByte <- getByte
      hasBlockByte <- getByte
      hasUndoByte <- getByte
      skip (Length 1)
      validationBlock <- if hasBlockByte /= 0
        then Just <$> getBytes validationSize
        else pure Nothing
      pure (description, imageTypeByte, hasBlockByte /= 0, hasUndoByte /= 0, validationBlock)

-- Pyriel's internal format (magic "PPF4"): 60-byte header, records with command byte +
-- 4-byte offsets.  Reverse-engineered from the Suikoden I/II bug fix patchers; not a
-- published spec — only ever generated and consumed within those patchers' Lua runtime.
parsePPF4 :: ByteString -> Either SlapError Patch
parsePPF4 input = wrapError LabelPPF4 $ runGet parsePPF4Body input
  where
    parsePPF4Body :: Get Patch
    parsePPF4Body = do
      skip (Length ppfDescriptionOffset)
      description <- getBytes (Length ppfDescriptionWidth)
      skip (Length (ppf4HeaderSize - ppfDescriptionOffset - ppfDescriptionWidth))
      records <- parseRecords4 LabelPPF4 0
      pure Patch
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
parseRecords32 :: FormatLabel -> Int -> Get [Record]
parseRecords32 label recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 5 then pure []
  else do
    recordOffset <- Offset . fromIntegral <$> word32LE
    count <- fromIntegral <$> getByte
    remainingAfterHeader <- remaining
    if unLength remainingAfterHeader < count
      then fail (truncatedMessage label recordIndex (5 + count) (unLength remainingBytes))
      else do
        payload <- getBytes (Length count)
        rest <- parseRecords32 label (recordIndex + 1)
        pure (Record recordOffset payload Nothing Replace : rest)

-- Parse PPF3 records (8-byte offset, 1-byte count, N bytes data, optional undo).
parseRecords64 :: FormatLabel -> Bool -> Int -> Get [Record]
parseRecords64 label hasUndo recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 9 then pure []
  else do
    recordOffset <- Offset <$> int64LE
    count <- fromIntegral <$> getByte
    let need = 9 + count + if hasUndo then count else 0
    if need > unLength remainingBytes
      then fail (truncatedMessage label recordIndex need (unLength remainingBytes))
      else do
        payload <- getBytes (Length count)
        undoData <- if hasUndo
                    then Just <$> getBytes (Length count)
                    else pure Nothing
        rest <- parseRecords64 label hasUndo (recordIndex + 1)
        pure (Record recordOffset payload undoData Replace : rest)

-- Parse PPF4 records (1-byte cmd, 4-byte offset, 1-byte count, N bytes data).
parseRecords4 :: FormatLabel -> Int -> Get [Record]
parseRecords4 label recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 6 then pure []
  else do
    commandByte <- getByte
    let command = if commandByte == 1 then Append else Replace
    recordOffset <- Offset . fromIntegral <$> word32LE
    count <- fromIntegral <$> getByte
    remainingAfterHeader <- remaining
    if unLength remainingAfterHeader < count
      then fail (truncatedMessage label recordIndex (6 + count) (unLength remainingBytes))
      else do
        payload <- getBytes (Length count)
        rest <- parseRecords4 label (recordIndex + 1)
        pure (Record recordOffset payload Nothing command : rest)

-- Format a truncated-record error message.
truncatedMessage :: FormatLabel -> Int -> Int -> Int -> String
truncatedMessage label recordIndex needed available =
  show label ++ ": record " ++ show recordIndex
  ++ " truncated (need " ++ show needed ++ " bytes, " ++ show available ++ " available)"

----------------------------------------------------------------------------
-- File_ID.diz detection (operates on the full input ByteString)
----------------------------------------------------------------------------

-- File_ID.diz detection, parameterised by length-field reader and width.
detectFileId :: (Integral a) => (Int -> ByteString -> a) -> Int -> ByteString -> Maybe FileId
detectFileId readLength lengthSize input
  | ByteString.length input < 4 + lengthSize = Nothing
  | ByteString.take 4 (ByteString.drop (ByteString.length input - 4 - lengthSize) input) == ".DIZ" =
      let idLength    = fromIntegral (readLength (ByteString.length input - lengthSize) input)
          trailerSize = fileIdMarkerSize + idLength + fileIdFooterSize + lengthSize
      in Just (FileId (ByteString.take idLength (ByteString.drop (ByteString.length input - trailerSize + fileIdMarkerSize) input)))
  | otherwise = Nothing

-- Strip File_ID.diz trailer bytes from the record body.
stripFileId :: Int -> Maybe FileId -> ByteString -> ByteString
stripFileId _ Nothing body = body
stripFileId lengthSize (Just (FileId content)) body =
  ByteString.take (ByteString.length body - fileIdMarkerSize - ByteString.length content - fileIdFooterSize - lengthSize) body
