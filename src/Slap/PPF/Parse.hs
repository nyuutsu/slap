{-# LANGUAGE OverloadedStrings #-}

module Slap.PPF.Parse (parsePatch) where

-- Canonical reference: reverse-engineered from Icarus/PPF-Studio; no formal spec
-- Secondary: RomPatcher.js modules/RomPatcher.format.ppf.js

import Slap.PPF.Types
import Slap.Binary (getWord16LE, getWord32LE, getInt64LE)
import Slap.Error (SlapError(..), FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
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
parsePPF1 input = do
  requireLength LabelPPF1 56 input
  records <- parseRecords32 LabelPPF1 (ByteString.drop 56 input)
  Right Patch
    { ppfVersion     = PPF1
    , ppfDescription = ByteString.take 50 (ByteString.drop 6 input)
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
  requireLength LabelPPF2 1084 input
  let fileId = detectFileId getWord32LE 4 input
      body   = stripFileId 4 fileId (ByteString.drop 1084 input)
  records <- parseRecords32 LabelPPF2 body
  Right Patch
    { ppfVersion     = PPF2
    , ppfDescription = ByteString.take 50 (ByteString.drop 6 input)
    , ppfFileSize    = Just (FileSize (fromIntegral (getWord32LE 56 input)))
    , ppfValidation  = Just (Validation BIN (ByteString.take 1024 (ByteString.drop 60 input)))
    , ppfHasUndo     = False
    , ppfImageType   = Nothing
    , ppfRecords     = records
    , ppfFileId      = fileId
    }

-- PPF3: 60 or 1084-byte header, then records with 8-byte offsets, optional undo.
parsePPF3 :: ByteString -> Either SlapError Patch
parsePPF3 input = do
  requireLength LabelPPF3 60 input
  imageType <- case ByteString.index input 56 of
    0x00 -> Right BIN
    0x01 -> Right GI
    byte -> Left (UnknownFlag LabelPPF3 FieldImageType byte)
  let hasBlock   = ByteString.index input 57 /= 0
      hasUndo    = ByteString.index input 58 /= 0
      ppf3HeaderSize = if hasBlock then 1084 else 60
  requireLength LabelPPF3 ppf3HeaderSize input
  let validation = if hasBlock
        then Just (Validation imageType (ByteString.take 1024 (ByteString.drop 60 input)))
        else Nothing
      fileId = detectFileId getWord16LE 2 input
      body   = stripFileId 2 fileId (ByteString.drop ppf3HeaderSize input)
  records <- parseRecords64 LabelPPF3 hasUndo body
  Right Patch
    { ppfVersion     = PPF3
    , ppfDescription = ByteString.take 50 (ByteString.drop 6 input)
    , ppfFileSize    = Nothing
    , ppfValidation  = validation
    , ppfHasUndo     = hasUndo
    , ppfImageType   = Just imageType
    , ppfRecords     = records
    , ppfFileId      = fileId
    }

-- Pyriel's internal format (magic "PPF4"): 60-byte header, records with command byte +
-- 4-byte offsets.  Reverse-engineered from the Suikoden I/II bug fix patchers; not a
-- published spec — only ever generated and consumed within those patchers' Lua runtime.
parsePPF4 :: ByteString -> Either SlapError Patch
parsePPF4 input = do
  requireLength LabelPPF4 60 input
  records <- parseRecords4 LabelPPF4 (ByteString.drop 60 input)
  Right Patch
    { ppfVersion     = PPF4
    , ppfDescription = ByteString.take 50 (ByteString.drop 6 input)
    , ppfFileSize    = Nothing
    , ppfValidation  = Nothing
    , ppfHasUndo     = False
    , ppfImageType   = Nothing
    , ppfRecords     = records
    , ppfFileId      = Nothing
    }

-- Parse PPF1/PPF2 records (4-byte offset, 1-byte count, N bytes data).
parseRecords32 :: FormatLabel -> ByteString -> Either SlapError [Record]
parseRecords32 label = parseLoop [] 0
  where
    parseLoop accumulated recordIndex input
      | ByteString.length input < 5 = Right (reverse accumulated)
      | 5 + count > ByteString.length input =
          Left (TruncatedRecord label recordIndex (Length (5 + count)) (Length (ByteString.length input)))
      | otherwise =
          parseLoop (Record recordOffset (ByteString.take count (ByteString.drop 5 input)) Nothing Replace : accumulated)
                    (recordIndex + 1)
                    (ByteString.drop (5 + count) input)
      where
        recordOffset = Offset (fromIntegral (getWord32LE 0 input))
        count  = fromIntegral (ByteString.index input 4) :: Int

-- Parse PPF3 records (8-byte offset, 1-byte count, N bytes data, optional undo).
parseRecords64 :: FormatLabel -> Bool -> ByteString -> Either SlapError [Record]
parseRecords64 label hasUndo = parseLoop [] 0
  where
    parseLoop accumulated recordIndex input
      | ByteString.length input < 9 = Right (reverse accumulated)
      | need > ByteString.length input =
          Left (TruncatedRecord label recordIndex (Length need) (Length (ByteString.length input)))
      | otherwise =
          parseLoop (Record recordOffset payload undoData Replace : accumulated) (recordIndex + 1) (ByteString.drop need input)
      where
        recordOffset = Offset (getInt64LE 0 input)
        count   = fromIntegral (ByteString.index input 8) :: Int
        payload = ByteString.take count (ByteString.drop 9 input)
        undoData = if hasUndo
                   then Just (ByteString.take count (ByteString.drop (9 + count) input))
                   else Nothing
        need    = 9 + count + if hasUndo then count else 0

-- Parse PPF4 records (1-byte cmd, 4-byte offset, 1-byte count, N bytes data).
parseRecords4 :: FormatLabel -> ByteString -> Either SlapError [Record]
parseRecords4 label = parseLoop [] 0
  where
    parseLoop accumulated recordIndex input
      | ByteString.length input < 6 = Right (reverse accumulated)
      | 6 + count > ByteString.length input =
          Left (TruncatedRecord label recordIndex (Length (6 + count)) (Length (ByteString.length input)))
      | otherwise =
          parseLoop (Record recordOffset (ByteString.take count (ByteString.drop 6 input)) Nothing command : accumulated)
                    (recordIndex + 1)
                    (ByteString.drop (6 + count) input)
      where
        command = if ByteString.index input 0 == 1 then Append else Replace
        recordOffset = Offset (fromIntegral (getWord32LE 1 input))
        count   = fromIntegral (ByteString.index input 5) :: Int

-- File_ID.diz detection, parameterised by length-field reader and width.
detectFileId :: (Integral a) => (Int -> ByteString -> a) -> Int -> ByteString -> Maybe FileId
detectFileId readLength lengthSize input
  | ByteString.length input < 4 + lengthSize = Nothing
  | ByteString.take 4 (ByteString.drop (ByteString.length input - 4 - lengthSize) input) == ".DIZ" =
      let idLength    = fromIntegral (readLength (ByteString.length input - lengthSize) input)
          trailerSize = 18 + idLength + 16 + lengthSize
      in Just (FileId (ByteString.take idLength (ByteString.drop (ByteString.length input - trailerSize + 18) input)))
  | otherwise = Nothing

-- Strip File_ID.diz trailer bytes from the record body.
stripFileId :: Int -> Maybe FileId -> ByteString -> ByteString
stripFileId _ Nothing body = body
stripFileId lengthSize (Just (FileId content)) body =
  ByteString.take (ByteString.length body - 18 - ByteString.length content - 16 - lengthSize) body

requireLength :: FormatLabel -> Int -> ByteString -> Either SlapError ()
requireLength label minLength input
  | ByteString.length input >= minLength = Right ()
  | otherwise = Left (InputTooShort label (Length minLength) (Length (ByteString.length input)))
