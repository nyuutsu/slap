{-# LANGUAGE OverloadedStrings #-}

module Slap.DPS.Create
  ( createDPS
  , dpsRecordsFromDiff
  , encodeRecord
  ) where

import Slap.DPS.Types (DPSCreateMetadata(..), DPSStability, fromDPSStability,
                       DPSFormatVersion(..), fromDPSFormatVersion,
                       DPSRecord(..), EncodedDPSRecord(..),
                       narrowDPSRecords, narrowDPSSourceSize,
                       unDPSSourceSize, dpsFieldWidth)
import Slap.Binary (putWord32LE, diffHunks)
import Slap.Measure (Offset(..), Hunk(..), byteFileSize, byteLength,
                     distance, hunkEnd, lengthToOffset, unLength)
import Slap.Text (EncodedText, EncodingName(..),
                  encodedTextContent, encodeTextBounded, encodeLossAdvisories)
import Slap.Status (SlapError, SlapAdvisory, CreateResult(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))

import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)

-- Encodes changed regions as EnclosedData records and unchanged regions
-- as CopyFromROM records. The source size and the record list are run
-- through the per-format narrowing layer first; downstream the encoder
-- consumes 'EncodedDPSRecord' values whose 'Word32' offsets and lengths
-- have already been validated against the wire-format width.
createDPS :: InputFileContents -> OutputFileContents
          -> DPSCreateMetadata -> DPSStability
          -> Either SlapError CreateResult
createDPS inputContents@(InputFileContents original) outputContents metadata stability = do
  sourceSize <- narrowDPSSourceSize (byteFileSize original)
  records    <- narrowDPSRecords (dpsRecordsFromDiff inputContents outputContents)
  let (nameBytes,    nameWarnings)    = encodeField FieldPatchName (dpsCreateMetadataName    metadata)
      (authorBytes,  authorWarnings)  = encodeField FieldAuthor    (dpsCreateMetadataAuthor  metadata)
      (versionBytes, versionWarnings) = encodeField FieldVersion   (dpsCreateMetadataVersion metadata)
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
    -- | Codepoint-aware bounded encode of one 64-byte metadata field,
    -- null-padded on the right. The @0x00@ padding byte matches DPS's
    -- reference encoder; both substitution and truncation notices
    -- surface as 'SlapAdvisory' values tagged with the field name.
    encodeField :: FieldName -> EncodedText
                -> (ByteString, [SlapAdvisory])
    encodeField fieldName fieldText =
      let (truncatedBytes, notices) =
            encodeTextBounded EncodingUtf8 dpsFieldWidth (encodedTextContent fieldText)
          padded = truncatedBytes
                <> ByteString.replicate
                     (max 0 (unLength dpsFieldWidth - ByteString.length truncatedBytes))
                     0x00
          advisories = encodeLossAdvisories LabelDPS fieldName notices
      in (padded, advisories)

dpsRecordsFromDiff :: InputFileContents -> OutputFileContents -> [DPSRecord]
dpsRecordsFromDiff _sourceContents (OutputFileContents modified) | ByteString.null modified = []
dpsRecordsFromDiff inputContents outputContents@(OutputFileContents modified) =
  buildRecords (Offset 0) (diffHunks inputContents outputContents)
  where
    modifiedEnd = lengthToOffset (byteLength modified)
    trailingCopy outputCursor
      | outputCursor < modifiedEnd =
          [DPSCopyFromROM outputCursor outputCursor (distance outputCursor modifiedEnd)]
      | otherwise = []
    buildRecords outputCursor [] = trailingCopy outputCursor
    buildRecords outputCursor (currentHunk : rest) =
      let hunkStart  = hunkOffset currentHunk
          dataRecord = DPSEnclosedData hunkStart (hunkPayload currentHunk)
          continue   = buildRecords (hunkEnd currentHunk) rest
      in if hunkStart > outputCursor
         then DPSCopyFromROM outputCursor outputCursor (distance outputCursor hunkStart)
              : dataRecord : continue
         else dataRecord : continue

-- | Serialise an 'EncodedDPSRecord' to wire bytes. The 'Word32'
-- selectors carry values 'narrowDPSRecord' already validated against the
-- 4-byte LE wire fields, so the surviving 'fromIntegral' (the payload
-- length on the 'EnclosedData' arm) cannot truncate: the smart
-- constructor checked that bytestring's length on the way in.
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
