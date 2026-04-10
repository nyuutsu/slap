{-# LANGUAGE OverloadedStrings #-}

module Slap.PPF.Create (encodePPF3, encodeFileIdDiz) where

import Slap.PPF.Types (PPFImageType(..), fromImageType, ppfDescriptionLength)
import Slap.Measure (Length(..), Offset(..), Hunk(..), UndoHunk(..),
                     OriginalLength(..), TruncatedLength(..))
import Slap.TextEncoding (BoundedResult(..), TruncationInfo(..), encodeBoundedLocale)
import Slap.Error (SlapWarning(..), CreateResult(..), FieldName(..))
import Slap.FormatLabel (FormatLabel(..))

import qualified Data.ByteString as ByteString
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Maybe (fromMaybe, isJust)

padDescription :: String -> CreateResult
padDescription text =
  let result = encodeBoundedLocale (unLength ppfDescriptionLength) text
      warnings = case boundedTruncation result of
        Nothing -> []
        Just info -> [FieldTruncated LabelPPF3 FieldDescription
                       (OriginalLength (truncatedFrom info)) (TruncatedLength (truncatedTo info))]
  in CreateResult (boundedField result) warnings

buildHeader :: ByteString -> Bool -> Bool -> ByteString -> PPFImageType -> Builder
buildHeader description blockCheck hasUndo validationBlock imageType =
  byteString "PPF30"                                    -- magic + version
  <> word8 0x02                                          -- encoding method
  <> byteString description                              -- 50-byte description
  <> word8 (fromImageType imageType)                       -- image type
  <> word8 (if blockCheck then 0x01 else 0x00)           -- block check flag
  <> word8 (if hasUndo then 0x01 else 0x00)              -- undo flag
  <> word8 0x00                                          -- dummy
  <> if blockCheck then byteString validationBlock else mempty  -- 1024-byte validation block

encodeUndoRecord :: Bool -> UndoHunk -> Builder
encodeUndoRecord hasUndo (UndoHunk hunkOffset hunkPayload hunkOriginal) =
  int64LE (fromIntegral (unOffset hunkOffset))
  <> word8 (fromIntegral (ByteString.length hunkPayload))
  <> byteString hunkPayload
  <> if hasUndo then byteString hunkOriginal else mempty

-- | Encode a PPF3 patch from pre-split records.
-- Records: [Hunk], each payload ≤ 255 bytes.
-- Undo hunks (if provided): [UndoHunk], each ≤ 255 bytes.
encodePPF3 :: [Hunk]
           -> String
           -> Maybe [UndoHunk]
           -> Maybe ByteString
           -> PPFImageType
           -> CreateResult
encodePPF3 records description undoHunks validationBlock imageType =
  let descResult = padDescription description
      hasValidate = isJust validationBlock
      hasUndo     = isJust undoHunks
      validationBytes = fromMaybe ByteString.empty validationBlock
      header      = buildHeader (resultBytes descResult) hasValidate hasUndo
                      validationBytes imageType
      body = case undoHunks of
        Just hunks -> foldMap (encodeUndoRecord True) hunks
        Nothing    -> foldMap encodeWriteRecord records
  in CreateResult (LazyByteString.toStrict (toLazyByteString (header <> body))) (resultWarnings descResult)

-- | Encode a write record (no undo data).
encodeWriteRecord :: Hunk -> Builder
encodeWriteRecord (Hunk hunkOffset hunkPayload) =
  int64LE (fromIntegral (unOffset hunkOffset))
  <> word8 (fromIntegral (ByteString.length hunkPayload))
  <> byteString hunkPayload

-- | Encode a File_ID.diz trailer in PPF3 format (2-byte LE length).
encodeFileIdDiz :: ByteString -> ByteString
encodeFileIdDiz content = LazyByteString.toStrict $ toLazyByteString $
  byteString "@BEGIN_FILE_ID.DIZ"
  <> byteString content
  <> byteString "@END_FILE_ID.DIZ"
  <> word16LE (fromIntegral (ByteString.length content))
