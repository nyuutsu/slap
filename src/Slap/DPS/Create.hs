{-# LANGUAGE OverloadedStrings #-}

module Slap.DPS.Create
  ( createDPS
  , dpsRecordsFromDiff
  , encodeRecord
  ) where

import Slap.DPS.Types (DPSMetadata(..), DPSStability, fromDPSStability, DPSFormatVersion(..), fromDPSFormatVersion, DPSRecord(..), dpsFieldWidth)
import Slap.Binary (putWord32LE, diffHunks)
import Slap.Measure (Offset(..), Length(..), Hunk(..),
                     OriginalLength(..), TruncatedLength(..))
import Slap.TextEncoding (BoundedResult(..), TruncationInfo(..), encodeBoundedLocale)
import Slap.Error (SlapError, SlapWarning(..), CreateResult(..), FieldName(..))
import Slap.FormatLabel (FormatLabel(..))

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Word (Word32)

-- Encodes changed regions as EnclosedData records and unchanged regions
-- as CopyFromROM records. Returns 'Either' for parity with the other
-- diff-format create entry points; DPS has no current failure modes,
-- so the result is always 'Right'.
createDPS :: SourceFileContents -> TargetFileContents -> DPSMetadata -> DPSStability
          -> Either SlapError CreateResult
createDPS (SourceFileContents original) (TargetFileContents modified) metadata stability =
    let (nameBytes, nameWarnings)       = encodeField FieldPatchName (dpsMetadataName metadata)
        (authorBytes, authorWarnings)   = encodeField FieldAuthor (dpsMetadataAuthor metadata)
        (versionBytes, versionWarnings) = encodeField FieldVersion (dpsMetadataVersion metadata)
        patchBytes = LazyByteString.toStrict $ toLazyByteString $
            byteString nameBytes
            <> byteString authorBytes
            <> byteString versionBytes
            <> word8 (fromDPSStability stability)
            <> word8 (fromDPSFormatVersion DPSVersion1)
            <> putWord32LE (fromIntegral (ByteString.length original) :: Word32)
            <> foldMap encodeRecord (dpsRecordsFromDiff original modified)
    in Right (CreateResult (PatchFileContents patchBytes)
                           (nameWarnings ++ authorWarnings ++ versionWarnings))
  where
    encodeField fieldName fieldString =
      let result = encodeBoundedLocale dpsFieldWidth fieldString
          warnings = case boundedTruncation result of
            Nothing -> []
            Just info -> [FieldTruncated LabelDPS fieldName
                           (OriginalLength (truncatedFrom info)) (TruncatedLength (truncatedTo info))]
      in (boundedField result, warnings)

dpsRecordsFromDiff :: ByteString -> ByteString -> [DPSRecord]
dpsRecordsFromDiff _original modified | ByteString.null modified = []
dpsRecordsFromDiff original modified = buildRecords 0 (diffHunks original modified)
  where
    modifiedLength = ByteString.length modified
    trailingCopy position
      | position < modifiedLength =
          [DPSCopyFromROM (Offset position)
             (Offset position) (Length (modifiedLength - position))]
      | otherwise = []
    buildRecords position [] = trailingCopy position
    buildRecords position (Hunk rawOffset rawData : rest) =
      let intOffset = unOffset rawOffset
      in if intOffset > position
         then DPSCopyFromROM (Offset position)
                (Offset position) (Length (intOffset - position))
              : DPSEnclosedData rawOffset rawData
              : buildRecords (intOffset + ByteString.length rawData) rest
         else DPSEnclosedData rawOffset rawData
              : buildRecords (intOffset + ByteString.length rawData) rest

encodeRecord :: DPSRecord -> Builder
encodeRecord (DPSCopyFromROM outputOffset sourceOffset copyLength) =
    word8 0
    <> putWord32LE (fromIntegral (unOffset outputOffset) :: Word32)
    <> putWord32LE (fromIntegral (unOffset sourceOffset) :: Word32)
    <> putWord32LE (fromIntegral (unLength copyLength) :: Word32)
encodeRecord (DPSEnclosedData outputOffset payload) =
    word8 1
    <> putWord32LE (fromIntegral (unOffset outputOffset) :: Word32)
    <> putWord32LE (fromIntegral (ByteString.length payload) :: Word32)
    <> byteString payload
