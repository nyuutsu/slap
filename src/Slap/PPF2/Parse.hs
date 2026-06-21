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
-- separately. Parallel to 'Slap.PPF3.Parse.PPF3ParsedHeader'.
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
      let (detectedFileId, fileIdAdvisories) = detectFileId metadataEncoding input
          fileId     = fmap fst detectedFileId
          recordBody = stripFileId detectedFileId
                          (ByteString.drop (unLength ppf2HeaderLength) input)
      header <- first (ParseError LabelPPF2) (runByteParser parsePPF2Header input)
      records <- first (ParseError LabelPPF2)
                       (runByteParser (parsePPF2Records firstAction) recordBody)
      pure (Parsed
        PPF2Patch
          { ppf2Description     = ppf2HeaderDescription header
          , ppf2SourceFileSize  = ppf2HeaderSourceFileSize header
          , ppf2ValidationBlock = ppf2HeaderValidationBlock header
          , ppf2Records         = records
          , ppf2FileId          = fileId
          }
        (ppf2HeaderDescriptionAdvisories header ++ fileIdAdvisories))
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
            (RemainingLength (lengthAddingHeader remainingAfterHeader)))
      | otherwise = do
          payload <- getBytes (Length payloadLength)
          pure (PPF2Record writeOffset payload)

    parseRleBody :: ActionIndex -> Length -> Offset -> ByteParser PPF2Record
    parseRleBody index remainingAfterHeader writeOffset
      | unLength remainingAfterHeader < 2 =
          throwByteParserError (ByteParserTruncatedRecord index
            (RequiredLength (Length 7))
            (RemainingLength (lengthAddingHeader remainingAfterHeader)))
      | otherwise = do
          dataByte <- getByte
          repeatCount <- fromIntegral <$> getByte
          pure (PPF2Record writeOffset (ByteString.replicate repeatCount dataByte))

    lengthAddingHeader :: Length -> Length
    lengthAddingHeader (Length availableAfterHeader) = Length (5 + availableAfterHeader)


----------------------------------------------------------------------------
-- FILE_ID.DIZ trailer detection (PPF2-specific 4-byte length field)
----------------------------------------------------------------------------

-- | Look at the very end of the patch for a FILE_ID.DIZ trailer.
-- The wire shape is:
--
-- "@BEGIN_FILE_ID.DIZ" then content, then "@END_FILE_ID.DIZ", then a
-- 4-byte LE32 length
--
-- with the @<length>@ four bytes naming the @<content>@ length and
-- letting us walk backwards to find the start. Returns 'Nothing' if
-- the "@END_FILE_ID.DIZ" marker isn't where the length suffix
-- says it should be. When the trailer is present, the content bytes
-- are decoded leniently under the chosen metadata encoding; any
-- decode substitutions surface as 'Slap.Status.FieldDecodedSubstituted'
-- advisories alongside the typed 'PPF2FileId'.
--
-- The wire-declared byte count is returned alongside the 'PPF2FileId'
-- so 'stripFileId' can size the trailer without re-encoding the typed text.
detectFileId :: EncodingName -> ByteString -> (Maybe (PPF2FileId, Int), [SlapAdvisory])
detectFileId metadataEncoding input
  | ByteString.length input < markerSize + lengthFieldSize = (Nothing, [])
  | ByteString.take markerSize trailerCandidate /= "@END_FILE_ID.DIZ" = (Nothing, [])
  | otherwise =
      let dizContentLength = fromIntegral (getWord32LE
                              (ByteString.length input - lengthFieldSize) input)
          dizContentEnd    = ByteString.length input - lengthFieldSize - markerSize
          dizContentStart  = dizContentEnd - dizContentLength
      in if dizContentStart < 0 then (Nothing, [])
         else let dizContentBytes = ByteString.take dizContentLength
                                      (ByteString.drop dizContentStart input)
                  (dizText, dizNotices) = decodeTextLenient metadataEncoding dizContentBytes
                  dizAdvisories = decodeLossAdvisories LabelPPF2 FieldFileIdDiz dizNotices
              in (Just (ppf2FileIdFromParsed dizText, dizContentLength), dizAdvisories)
  where
    markerSize        = unLength ppf2FileIdFooterLength
    lengthFieldSize   = unLength ppf2FileIdLengthFieldWidth
    trailerCandidate  = ByteString.drop (ByteString.length input - lengthFieldSize - markerSize)
                          (ByteString.take (ByteString.length input - lengthFieldSize) input)

-- | Trim the FILE_ID.DIZ trailer off the record body, if one was
-- detected. Leaves the body unchanged otherwise. The trailer size
-- is computed from the wire-declared content byte count plus the
-- fixed marker and length-field widths.
stripFileId :: Maybe (PPF2FileId, Int) -> ByteString -> ByteString
stripFileId Nothing body = body
stripFileId (Just (_, contentByteCount)) body =
  let trailerSize = unLength ppf2FileIdMarkerLength
                  + contentByteCount
                  + unLength ppf2FileIdFooterLength
                  + unLength ppf2FileIdLengthFieldWidth
  in ByteString.take (ByteString.length body - trailerSize) body
