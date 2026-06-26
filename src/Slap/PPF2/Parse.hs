{-# LANGUAGE OverloadedStrings #-}

-- | Parse a PPF2 patch from raw bytes. Spec:
-- @docs/ppf/upstream/pdx-ppf2/ppftools/ppfdev/PPF2.txt@. The PPF2
-- record stream wire format is identical to PPF1's (4-byte LE
-- offset, 1-byte count, payload, with count=0 meaning RLE), but
-- the spec text is silent on the RLE branch — the reference
-- applier treats both formats the same way and we follow it.
module Slap.PPF2.Parse (parsePPF2, parsePPF2Records) where

import Slap.PPF2.Types (PPF2Patch(..), PPF2Record(..),
                        PPF2ValidationBlock(..),
                        PPF2FileId, ppf2FileIdFromParsed,
                        PPF2SourceSize, ppf2SourceSizeFromParsed,
                        ppf2DescriptionLength, ppf2HeaderLength,
                        ppf2ValidationSize,
                        ppf2FileIdLengthFieldWidth,
                        ppf2FileIdMarkerLength, ppf2FileIdFooterLength)
import Slap.Binary (getWord32LE)
import Slap.Status (SlapError(..), SlapAdvisory, Parsed(..), ByteParserError(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runByteParser, throwByteParserError,
                        getByte, getBytes, remaining, skip, word32LE)
import Slap.Measure (Offset, offsetFromParsed, Length(..),
                     EncodingMethodByte(..),
                     ActionIndex,
                     RequiredLength(..), ActualLength(..), RemainingLength(..),
                     firstAction, nextAction, byteLength)
import Slap.Text (EncodedText, EncodingName(..),
                  decodeTextLenient, decodeLossAdvisories,
                  decodeFixedWidthTextField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bifunctor (first)

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
  | ByteString.length input < unLength minimumPPF2ParseLength =
      Left (InputTooShort LabelPPF2
              (RequiredLength minimumPPF2ParseLength)
              (ActualLength (byteLength input)))
  | otherwise = do
      () <- checkEncodingByte input
      let fileIdSplit = splitFileIdTrailer metadataEncoding ppf2HeaderLength input
      header <- first (ParseError LabelPPF2) (runByteParser parsePPF2Header input)
      records <- first (ParseError LabelPPF2)
                       (runByteParser (parsePPF2Records firstAction) (ppf2SplitRecordBody fileIdSplit))
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

-- | Same record-stream shape as PPF1, but kept as a separate per-format
-- copy so the two versions can diverge on their own producer quirks.
parsePPF2Records :: ActionIndex -> ByteParser [PPF2Record]
parsePPF2Records recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 5 then pure []
  else do
    recordOffset <- offsetFromParsed <$> word32LE
    countByte <- fromIntegral <$> getByte
    remainingAfterHeader <- remaining
    record <- if countByte == 0
      then parseRleBody recordIndex remainingAfterHeader recordOffset
      else parseLiteralBody recordIndex remainingAfterHeader recordOffset countByte
    rest <- parsePPF2Records (nextAction recordIndex)
    pure (record : rest)
  where
    parseLiteralBody :: ActionIndex -> Length -> Offset -> Int -> ByteParser PPF2Record
    parseLiteralBody index remainingAfterHeader writeOffset payloadLength
      | unLength remainingAfterHeader < payloadLength =
          throwByteParserError (ByteParserTruncatedRecord index
            (RequiredLength (Length (5 + payloadLength)))
            (RemainingLength (lengthWithRecordHeader remainingAfterHeader)))
      | otherwise = do
          payload <- getBytes (Length payloadLength)
          pure (PPF2Record writeOffset payload)

    parseRleBody :: ActionIndex -> Length -> Offset -> ByteParser PPF2Record
    parseRleBody index remainingAfterHeader writeOffset
      | unLength remainingAfterHeader < 2 =
          throwByteParserError (ByteParserTruncatedRecord index
            (RequiredLength (Length 7))
            (RemainingLength (lengthWithRecordHeader remainingAfterHeader)))
      | otherwise = do
          dataByte <- getByte
          repeatCount <- fromIntegral <$> getByte
          pure (PPF2Record writeOffset (ByteString.replicate repeatCount dataByte))

    lengthWithRecordHeader :: Length -> Length
    lengthWithRecordHeader (Length availableAfterHeader) = Length (5 + availableAfterHeader)


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
  | inputLength < markerSize + lengthFieldSize = withoutTrailer
  | trailerCandidate /= "@END_FILE_ID.DIZ"     = withoutTrailer
  | dizContentStart < 0                         = withoutTrailer
  | otherwise = PPF2FileIdSplit
      { ppf2SplitFileId     = Just (ppf2FileIdFromParsed dizText)
      , ppf2SplitRecordBody =
          ByteString.take (ByteString.length recordBody - trailerSize) recordBody
      , ppf2SplitAdvisories = decodeLossAdvisories LabelPPF2 FieldFileIdDiz dizNotices
      }
  where
    inputLength      = ByteString.length input
    markerSize       = unLength ppf2FileIdFooterLength
    lengthFieldSize  = unLength ppf2FileIdLengthFieldWidth
    recordBody       = ByteString.drop (unLength headerLength) input
    withoutTrailer   = PPF2FileIdSplit Nothing recordBody []

    lengthFieldStart = inputLength - lengthFieldSize
    markerStart      = lengthFieldStart - markerSize
    trailerCandidate = ByteString.take markerSize (ByteString.drop markerStart input)
    dizContentLength = fromIntegral (getWord32LE lengthFieldStart input)
    dizContentStart  = markerStart - dizContentLength
    (dizText, dizNotices) =
      decodeTextLenient metadataEncoding
        (ByteString.take dizContentLength (ByteString.drop dizContentStart input))
    trailerSize = unLength ppf2FileIdMarkerLength + dizContentLength
                + unLength ppf2FileIdFooterLength + unLength ppf2FileIdLengthFieldWidth
