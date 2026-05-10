{-# LANGUAGE OverloadedStrings #-}

module Slap.DPS.Create
  ( createDPS
  , dpsRecordsFromDiff
  , encodeRecord
  ) where

import Slap.DPS.Types (DPSMetadata(..), DPSStability, fromDPSStability,
                       DPSFormatVersion(..), fromDPSFormatVersion,
                       DPSRecord(..), EncodedDPSRecord(..),
                       narrowDPSRecords, narrowDPSSourceSize,
                       unDPSSourceSize, dpsFieldWidth)
import Slap.Binary (putWord32LE, diffHunks)
import Slap.Measure (Offset(..), Length(..), Hunk(..),
                     OriginalLength(..), TruncatedLength(..),
                     byteFileSize)
import Slap.TextEncoding (BoundedResult(..), TruncationInfo(..), encodeBoundedLocale)
import Slap.Error (SlapError, SlapWarning(..), CreateResult(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))

import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)

-- Encodes changed regions as EnclosedData records and unchanged regions
-- as CopyFromROM records. The source size and the record list are run
-- through the per-format narrowing layer first; downstream the encoder
-- consumes 'EncodedDPSRecord' values whose 'Word32' offsets and lengths
-- have already been validated against the wire-format width.
createDPS :: InputFileContents -> OutputFileContents -> DPSMetadata -> DPSStability
          -> Either SlapError CreateResult
createDPS inputContents@(InputFileContents original) outputContents metadata stability = do
  sourceSize <- narrowDPSSourceSize (byteFileSize original)
  records    <- narrowDPSRecords (dpsRecordsFromDiff inputContents outputContents)
  let (nameBytes, nameWarnings)       = encodeField FieldPatchName (dpsMetadataName metadata)
      (authorBytes, authorWarnings)   = encodeField FieldAuthor (dpsMetadataAuthor metadata)
      (versionBytes, versionWarnings) = encodeField FieldVersion (dpsMetadataVersion metadata)
      patchBytes = LazyByteString.toStrict $ toLazyByteString $
          byteString nameBytes
          <> byteString authorBytes
          <> byteString versionBytes
          <> word8 (fromDPSStability stability)
          <> word8 (fromDPSFormatVersion DPSVersion1)
          <> putWord32LE (unDPSSourceSize sourceSize)
          <> foldMap encodeRecord records
  Right (CreateResult (PatchFileContents patchBytes)
                      (nameWarnings ++ authorWarnings ++ versionWarnings))
  where
    encodeField fieldName fieldString =
      let result = encodeBoundedLocale dpsFieldWidth fieldString
          warnings = case boundedTruncation result of
            Nothing -> []
            Just info -> [FieldTruncated LabelDPS fieldName
                           (OriginalLength (truncatedFrom info)) (TruncatedLength (truncatedTo info))]
      in (boundedField result, warnings)

dpsRecordsFromDiff :: InputFileContents -> OutputFileContents -> [DPSRecord]
dpsRecordsFromDiff _sourceContents (OutputFileContents modified) | ByteString.null modified = []
dpsRecordsFromDiff inputContents outputContents@(OutputFileContents modified) =
  buildRecords 0 (diffHunks inputContents outputContents)
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

-- | Serialise an 'EncodedDPSRecord' to wire bytes. The 'Word32'
-- selectors carry values 'narrowDPSRecord' has already validated
-- against the 4-byte LE wire fields, so the only surviving
-- 'fromIntegral' (the payload length on the 'EnclosedData' arm) is
-- safe-by-construction — the smart constructor checked the same
-- bytestring's length on the way in.
encodeRecord :: EncodedDPSRecord -> Builder
encodeRecord (EncodedDPSCopyFromROM outputOffset sourceOffset copyLength) =
    word8 0
    <> putWord32LE outputOffset
    <> putWord32LE sourceOffset
    <> putWord32LE copyLength
encodeRecord (EncodedDPSEnclosedData outputOffset payload) =
    word8 1
    <> putWord32LE outputOffset
    <> putWord32LE (fromIntegral (ByteString.length payload))
    <> byteString payload
