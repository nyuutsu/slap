{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder for PPF3 patches. Records use 8-byte LE offsets,
-- a 1-byte payload-length count, and (when the patch's undo flag
-- is set) an equal-length undo payload after each write payload.
-- Optional FILE_ID.DIZ trailer is appended verbatim by the caller
-- after this function returns its bytes.
module Slap.PPF3.Create
  ( encodePPF3
  , encodeFileIdDiz
  , computeUndo
  ) where

import Slap.PPF3.Types (PPF3ImageType(..), PPF3FileId(..),
                        PPF3ValidationBlock(..),
                        fromImageType,
                        ppf3DescriptionLength, ppf3MaxRecordPayload)
import Slap.Measure (Length(..), Offset(..), Hunk(..), UndoHunk(..),
                     OriginalLength(..), TruncatedLength(..),
                     splitHunk, splitOffset, splitPayload)
import Slap.Narrow (EncodedHunk, encodedOffset, encodedPayload)
import Slap.TextEncoding (BoundedResult(..), TruncationInfo(..), encodeBoundedLocale)
import Slap.Error (SlapWarning(..), CreateResult(..), FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.FileContents (PatchFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Maybe (isJust)

padDescription :: String -> (ByteString, [SlapWarning])
padDescription text =
  let result = encodeBoundedLocale (unLength ppf3DescriptionLength) text
      warnings = case boundedTruncation result of
        Nothing   -> []
        Just info -> [FieldTruncated LabelPPF3 FieldDescription
                       (OriginalLength (truncatedFrom info))
                       (TruncatedLength (truncatedTo info))]
  in (boundedField result, warnings)

buildHeader :: ByteString -> Bool -> Bool -> ByteString -> PPF3ImageType -> Builder
buildHeader description blockCheck hasUndo validationBlock imageType =
  byteString "PPF30"                                    -- magic + version
  <> word8 0x02                                          -- encoding method
  <> byteString description                              -- 50-byte description
  <> word8 (fromImageType imageType)                     -- image type
  <> word8 (if blockCheck then 0x01 else 0x00)           -- block-check flag
  <> word8 (if hasUndo then 0x01 else 0x00)              -- undo flag
  <> word8 0x00                                          -- dummy
  <> if blockCheck then byteString validationBlock else mempty

encodeUndoRecord :: Bool -> UndoHunk -> Builder
encodeUndoRecord hasUndo (UndoHunk hunkOffset hunkPayload hunkOriginal) =
  int64LE (fromIntegral (unOffset hunkOffset))
  <> word8 (fromIntegral (ByteString.length hunkPayload))
  <> byteString hunkPayload
  <> if hasUndo then byteString hunkOriginal else mempty

encodeWriteRecord :: EncodedHunk -> Builder
encodeWriteRecord ehunk =
  int64LE (fromIntegral (unOffset (encodedOffset ehunk)))
  <> word8 (fromIntegral (ByteString.length (encodedPayload ehunk)))
  <> byteString (encodedPayload ehunk)

-- | Encode a PPF3 patch from pre-split, pre-narrowed records.
-- Write records: @[EncodedHunk]@, each payload ≤ 'ppf3MaxRecordPayload'
-- (offset is unbounded — Int64-shaped on the wire — so the convert
-- pipeline narrows via 'narrowHunksUnbounded').
-- Undo hunks (if provided): @[UndoHunk]@, each ≤ 'ppf3MaxRecordPayload'.
encodePPF3 :: [EncodedHunk]
           -> String
           -> Maybe [UndoHunk]
           -> Maybe PPF3ValidationBlock
           -> PPF3ImageType
           -> CreateResult
encodePPF3 records description undoHunks validationBlock imageType =
  let (descriptionBytes, descriptionWarnings) = padDescription description
      hasValidate = isJust validationBlock
      hasUndo     = isJust undoHunks
      validationBytes = maybe ByteString.empty unPPF3ValidationBlock validationBlock
      header = buildHeader descriptionBytes hasValidate hasUndo
                 validationBytes imageType
      body = case undoHunks of
        Just hunks -> foldMap (encodeUndoRecord True) hunks
        Nothing    -> foldMap encodeWriteRecord records
  in CreateResult
       (PatchFileContents (LazyByteString.toStrict (toLazyByteString (header <> body))))
       descriptionWarnings

-- | Encode a FILE_ID.DIZ trailer in PPF3 format (2-byte LE length).
encodeFileIdDiz :: PPF3FileId -> ByteString
encodeFileIdDiz (PPF3FileId content) = LazyByteString.toStrict $ toLazyByteString $
  byteString "@BEGIN_FILE_ID.DIZ"
  <> byteString content
  <> byteString "@END_FILE_ID.DIZ"
  <> word16LE (fromIntegral (ByteString.length content))

-- | Compute undo hunks from source bytes and diff records.
-- Each record is split at 'ppf3MaxRecordPayload'; the split's typed
-- output ('SplitHunk') flows through this helper as a payload-bound
-- proof, then materialises into 'UndoHunk's.
computeUndo :: ByteString -> [Hunk] -> [UndoHunk]
computeUndo source = concatMap toUndoHunks
  where
    sourceLength = ByteString.length source
    toUndoHunks h
      | ByteString.null (hunkPayload h) = []
      | otherwise = map toUndoHunk (splitHunk ppf3MaxRecordPayload h)
    toUndoHunk piece =
      let recordOffset  = splitOffset piece
          recordPayload = splitPayload piece
      in UndoHunk recordOffset recordPayload
                  (oldBytes (unOffset recordOffset) (ByteString.length recordPayload))
    oldBytes position chunkLength
      | position >= sourceLength = ByteString.replicate chunkLength 0
      | position + chunkLength > sourceLength =
          ByteString.take (sourceLength - position) (ByteString.drop position source)
          <> ByteString.replicate (chunkLength - (sourceLength - position)) 0
      | otherwise = ByteString.take chunkLength (ByteString.drop position source)
