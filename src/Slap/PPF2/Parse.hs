{-# LANGUAGE OverloadedStrings #-}

-- | Parse a PPF2 patch from raw bytes. Spec: @docs/ppf/upstream/pdx-ppf2/ppftools/ppfdev/PPF2.txt@.
-- A PPF2 record is a 4-byte LE offset, a 1-byte count, then @count@ payload bytes; a count of zero is a zero-length write.
module Slap.PPF2.Parse (parsePPF2, parsePPF2Records) where

import Slap.PPF2.Types (PPF2Patch(..), PPF2Record(..),
                        PPF2ValidationBlock(..),
                        PPF2FileId, ppf2FileIdFromParsed,
                        PPF2SourceSize, ppf2SourceSizeFromParsed,
                        ppf2DescriptionLength, ppf2HeaderLength,
                        ppf2ValidationSize,
                        ppf2FileIdLengthFieldWidth,
                        ppf2FileIdMarkerLength, ppf2FileIdFooterLength)
import Slap.Binary (getWord32LE, dropLength, dropLengthFromEnd, splitSuffixOfLength)
import Slap.Status (SlapError(..), SlapAdvisory, Parsed(..), ByteParserError(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, throwByteParserError,
                        getByte, getBytes, remaining, skip, word32LE)
import Slap.Measure (offsetFromParsed, Length(..),
                     EncodingMethodByte(..),
                     ActionIndex,
                     RequiredLength(..), ActualLength(..), RemainingLength(..),
                     firstAction, nextAction, byteLength)
import Slap.Text (EncodedText, EncodingName(..),
                  decodeTextLenient, decodeLossAdvisories,
                  decodeFixedWidthTextField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

-- | Intermediate result of running the PPF2 header parser. Reshaped
-- by 'parsePPF2' into the final 'PPF2Patch' once the trailing record
-- stream (and optional FILE_ID.DIZ trailer) have been parsed
-- separately.
data PPF2ParsedHeader = PPF2ParsedHeader
  { ppf2HeaderDescription           :: !EncodedText
  , ppf2HeaderDescriptionAdvisories :: ![SlapAdvisory]
  , ppf2HeaderSourceFileSize        :: !PPF2SourceSize
  , ppf2HeaderValidationBlock       :: !PPF2ValidationBlock
  }

parsePPF2 :: EncodingName -> PatchFileContents -> Either SlapError (Parsed PPF2Patch)
parsePPF2 metadataEncoding (PatchFileContents input)
  | byteLength input < minimumPPF2ParseLength =
      Left (InputTooShort LabelPPF2
              (RequiredLength minimumPPF2ParseLength)
              (ActualLength (byteLength input)))
  | otherwise = do
      () <- checkEncodingByte input
      let fileIdSplit = splitFileIdTrailer metadataEncoding ppf2HeaderLength input
      header <- runFormatParser LabelPPF2 parsePPF2Header input
      records <- runFormatParser LabelPPF2 (parsePPF2Records firstAction) (ppf2SplitRecordBody fileIdSplit)
      pure (Parsed
        PPF2Patch
          { ppf2Description     = ppf2HeaderDescription header
          , ppf2SourceFileSize  = ppf2HeaderSourceFileSize header
          , ppf2ValidationBlock = ppf2HeaderValidationBlock header
          , ppf2Records         = records
          , ppf2FileId          = ppf2SplitFileId fileIdSplit
          }
        (ppf2HeaderDescriptionAdvisories header ++ ppf2SplitAdvisories fileIdSplit))
  where
    parsePPF2Header :: ByteParser PPF2ParsedHeader
    parsePPF2Header = do
      skip (Length 6)
      descriptionBytes <- getBytes ppf2DescriptionLength
      let (descriptionText, descriptionAdvisories) =
            decodeFixedWidthTextField metadataEncoding LabelPPF2 FieldDescription descriptionBytes
      fileSize <- ppf2SourceSizeFromParsed <$> word32LE
      validationBlock <- PPF2ValidationBlock <$> getBytes ppf2ValidationSize
      pure PPF2ParsedHeader
        { ppf2HeaderDescription           = descriptionText
        , ppf2HeaderDescriptionAdvisories = descriptionAdvisories
        , ppf2HeaderSourceFileSize        = fileSize
        , ppf2HeaderValidationBlock       = validationBlock
        }

-- | Six bytes is enough to read magic + encoding byte; the deeper
-- header parser expects the full 1084 bytes when called.
minimumPPF2ParseLength :: Length
minimumPPF2ParseLength = Length 6

-- | Verify the encoding-method byte at offset 5 is @0x01@.
checkEncodingByte :: ByteString -> Either SlapError ()
checkEncodingByte input
  | actual == 0x01 = Right ()
  | otherwise      = Left (UnsupportedEncodingMethod LabelPPF2 (EncodingMethodByte actual))
  where actual = ByteString.index input 5

ppf2RecordHeaderLength :: Int
ppf2RecordHeaderLength = 5

parsePPF2Records :: ActionIndex -> ByteParser [PPF2Record]
parsePPF2Records recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < fromIntegral ppf2RecordHeaderLength then pure []
  else do
    recordOffset  <- offsetFromParsed <$> word32LE
    payloadLength <- fromIntegral <$> getByte
    let totalNeeded = ppf2RecordHeaderLength + payloadLength
    if fromIntegral totalNeeded > unLength remainingBytes
      then throwByteParserError (ByteParserTruncatedRecord recordIndex
             (RequiredLength (Length (fromIntegral totalNeeded)))
             (RemainingLength remainingBytes))
      else do
        payload <- getBytes (Length (fromIntegral payloadLength))
        rest    <- parsePPF2Records (nextAction recordIndex)
        pure (PPF2Record recordOffset payload : rest)


----------------------------------------------------------------------------
-- FILE_ID.DIZ trailer split (PPF2-specific 4-byte length field)
----------------------------------------------------------------------------

-- | The optional FILE_ID.DIZ trailer separated from a PPF2 record body:
-- the typed metadata when present, the record body with the trailer
-- removed, and any decode advisories.
data PPF2FileIdSplit = PPF2FileIdSplit
  { ppf2SplitFileId     :: !(Maybe PPF2FileId)
  , ppf2SplitRecordBody :: !ByteString
  , ppf2SplitAdvisories :: ![SlapAdvisory]
  }

-- | Detect and peel a PPF2 FILE_ID.DIZ trailer off the record body.
-- @headerLength@ marks where the body begins; the trailer, when
-- present, sits at the very end of @input@ with the wire shape
--
-- "@BEGIN_FILE_ID.DIZ" then content, then "@END_FILE_ID.DIZ", then a
-- 4-byte LE32 content length
--
-- whose length suffix lets us walk back to the content start. The
-- content is decoded leniently under the chosen metadata encoding; any
-- substitutions surface as 'Slap.Status.FieldDecodedSubstituted'
-- advisories. The on-wire content byte count stays a local here, sizing
-- the trim in place. An absent or unrecognized trailer (no
-- "@END_FILE_ID.DIZ" where the suffix points) leaves the body as the
-- whole post-header slice.
splitFileIdTrailer :: EncodingName -> Length -> ByteString -> PPF2FileIdSplit
splitFileIdTrailer metadataEncoding headerLength input
  | byteLength input < ppf2FileIdFooterLength <> ppf2FileIdLengthFieldWidth = withoutTrailer
  | footerCandidate /= "@END_FILE_ID.DIZ"                                   = withoutTrailer
  | dizContentLength > byteLength bytesBeforeFooter                         = withoutTrailer
  | otherwise = PPF2FileIdSplit
      { ppf2SplitFileId     = Just (ppf2FileIdFromParsed dizText)
      , ppf2SplitRecordBody = dropLengthFromEnd trailerSize recordBody
      , ppf2SplitAdvisories = decodeLossAdvisories LabelPPF2 FieldFileIdDiz dizNotices
      }
  where
    recordBody     = dropLength headerLength input
    withoutTrailer = PPF2FileIdSplit Nothing recordBody []

    (bytesBeforeLengthField, lengthFieldBytes) = splitSuffixOfLength ppf2FileIdLengthFieldWidth input
    (bytesBeforeFooter, footerCandidate)       = splitSuffixOfLength ppf2FileIdFooterLength bytesBeforeLengthField
    (_, dizContentBytes)                       = splitSuffixOfLength dizContentLength bytesBeforeFooter
    dizContentLength      = Length (fromIntegral (getWord32LE 0 lengthFieldBytes))
    (dizText, dizNotices) = decodeTextLenient metadataEncoding dizContentBytes
    trailerSize = ppf2FileIdMarkerLength <> dizContentLength
               <> ppf2FileIdFooterLength <> ppf2FileIdLengthFieldWidth
