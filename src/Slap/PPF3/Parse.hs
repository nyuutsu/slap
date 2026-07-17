{-# LANGUAGE OverloadedStrings #-}

-- | Parse a PPF3 patch from raw bytes.
-- Spec: @ppfdev/PPF3.txt@ in @docs/ppf/upstream/ppf-master.zip@.
-- Reference applier (canonical for the on-wire byte-walk semantics): @ppfdev/applyppf_src/applyppf3_linux.c@ in @docs/ppf/upstream/ppf-master.zip@.
module Slap.PPF3.Parse (parsePPF3, parsePPF3Records) where

import Slap.PPF3.Types (PPF3Patch(..), PPF3Record(..),
                        PPF3ImageType(..), PPF3ValidationBlock(..),
                        PPF3CarriedFileId(..),
                        ppf3PreambleLength, ppf3RecordHeaderLength,
                        ppf3DescriptionLength, ppf3MinHeaderLength,
                        ppf3ValidationSize,
                        ppf3FileIdLengthFieldWidth, ppf3FileIdMaxContentLength,
                        ppf3FileIdMarkerLength, ppf3FileIdFooterLength)
import Slap.Binary (getWord16LE, dropLength, dropLengthFromEnd, splitSuffixOfLength)
import Slap.Status (SlapError(..), SlapAdvisory(..), Parsed(..), ByteParserError(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, parseWhen, throwByteParserError,
                        getByte, getBytes, remaining, skip, int64LE)
import Slap.Measure (offsetFromParsed, Length(..), EncodingMethodByte(..),
                     RawFlagByte(..),
                     ActionIndex,
                     RequiredLength(..), ActualLength(..), RemainingLength(..), MaxLength(..),
                     firstAction, nextAction, byteLength)
import Slap.Text (EncodedText, EncodingName(..),
                  decodeTextLenient, decodeLossAdvisories, substitutionCount,
                  decodeFixedWidthTextField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)

-- | Intermediate result of parsing the PPF3 fixed-header fields.
data PPF3ParsedHeader = PPF3ParsedHeader
  { ppf3HeaderDescription     :: !EncodedText
  , ppf3HeaderDescriptionAdvisories :: ![SlapAdvisory]
  , ppf3HeaderImageTypeByte   :: !Word8
  , ppf3HeaderHasBlockCheck   :: !Bool
  , ppf3HeaderHasUndo         :: !Bool
  , ppf3HeaderValidationBlock :: !(Maybe PPF3ValidationBlock)
  }

parsePPF3 :: EncodingName -> PatchFileContents -> Either SlapError (Parsed PPF3Patch)
parsePPF3 metadataEncoding (PatchFileContents input)
  | byteLength input < minimumPPF3ParseLength =
      Left (InputTooShort LabelPPF3
              (RequiredLength minimumPPF3ParseLength)
              (ActualLength (byteLength input)))
  | otherwise = do
      () <- checkEncodingByte input
      header <- runFormatParser LabelPPF3 parseHeader input
      imageType <- case ppf3HeaderImageTypeByte header of
        0x00 -> Right BIN
        0x01 -> Right GI
        byte -> Left (UnknownFlag LabelPPF3 FieldImageType (RawFlagByte byte))
      let headerLength = if ppf3HeaderHasBlockCheck header
                           then ppf3MinHeaderLength <> ppf3ValidationSize
                           else ppf3MinHeaderLength
          fileIdSplit = splitFileIdTrailer metadataEncoding (dropLength headerLength input)
      records <- runFormatParser LabelPPF3 (parsePPF3Records (ppf3HeaderHasUndo header) firstAction)
                                           (ppf3SplitRecordBody fileIdSplit)
      pure (Parsed
        PPF3Patch
          { ppf3Description     = ppf3HeaderDescription header
          , ppf3ImageType       = imageType
          , ppf3HasUndo         = ppf3HeaderHasUndo header
          , ppf3ValidationBlock = ppf3HeaderValidationBlock header
          , ppf3Records         = records
          , ppf3FileId          = ppf3SplitFileId fileIdSplit
          }
        (ppf3HeaderDescriptionAdvisories header ++ ppf3SplitAdvisories fileIdSplit))
  where
    parseHeader :: ByteParser PPF3ParsedHeader
    parseHeader = do
      skip ppf3PreambleLength
      descriptionBytes <- getBytes ppf3DescriptionLength
      let (descriptionText, descriptionAdvisories) =
            decodeFixedWidthTextField metadataEncoding LabelPPF3 FieldDescription descriptionBytes
      imageTypeByte <- getByte
      hasBlockByte <- getByte
      hasUndoByte <- getByte
      skip (Length 1)
      validationBlock <- parseWhen (hasBlockByte /= 0) (PPF3ValidationBlock <$> getBytes ppf3ValidationSize)
      pure PPF3ParsedHeader
        { ppf3HeaderDescription           = descriptionText
        , ppf3HeaderDescriptionAdvisories = descriptionAdvisories
        , ppf3HeaderImageTypeByte         = imageTypeByte
        , ppf3HeaderHasBlockCheck         = hasBlockByte /= 0
        , ppf3HeaderHasUndo               = hasUndoByte /= 0
        , ppf3HeaderValidationBlock       = validationBlock
        }

-- | Minimum bytes 'parsePPF3' needs before indexing: the preamble, so
-- 'checkEncodingByte' can read the encoding byte at offset 5 and
-- 'parseHeader' can skip past it.
minimumPPF3ParseLength :: Length
minimumPPF3ParseLength = ppf3PreambleLength

checkEncodingByte :: ByteString -> Either SlapError ()
checkEncodingByte input
  | actual == 0x02 = Right ()
  | otherwise      = Left (UnsupportedEncodingMethod LabelPPF3 (EncodingMethodByte actual))
  where actual = ByteString.index input 5

-- | Parse PPF3 records. PPF3 uses 8-byte LE offsets and has no
-- count=0 RLE sentinel, but each record optionally carries an
-- equal-length undo-bytes payload after the write payload (when
-- the parent patch's undo flag is set).
parsePPF3Records :: Bool -> ActionIndex -> ByteParser [PPF3Record]
parsePPF3Records hasUndo recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < unLength ppf3RecordHeaderLength then pure []
  else do
    recordOffset <- offsetFromParsed <$> int64LE
    payloadLength <- fromIntegral <$> getByte
    let totalNeeded = unLength ppf3RecordHeaderLength + payloadLength + (if hasUndo then payloadLength else 0)
    if totalNeeded > unLength remainingBytes
      then throwByteParserError (ByteParserTruncatedRecord recordIndex
             (RequiredLength (Length totalNeeded))
             (RemainingLength remainingBytes))
      else do
        payload <- getBytes (Length payloadLength)
        undoPayload <- if hasUndo
                         then Just <$> getBytes (Length payloadLength)
                         else pure Nothing
        rest <- parsePPF3Records hasUndo (nextAction recordIndex)
        pure (PPF3Record recordOffset payload undoPayload : rest)


----------------------------------------------------------------------------
-- FILE_ID.DIZ trailer split (PPF3-specific 2-byte length field)
----------------------------------------------------------------------------

-- | The optional FILE_ID.DIZ trailer separated from a PPF3 record body;
-- 'ppf3SplitRecordBody' has the trailer already removed.
data PPF3FileIdSplit = PPF3FileIdSplit
  { ppf3SplitFileId     :: !(Maybe PPF3CarriedFileId)
  , ppf3SplitRecordBody :: !ByteString
  , ppf3SplitAdvisories :: ![SlapAdvisory]
  }

-- | Detect and peel a PPF3 FILE_ID.DIZ trailer off the record body — the post-header slice,
-- which is all this function is handed, so no declared length can reach back to bytes in the header.
-- The trailer, when present, sits at the very end of the body,
-- its content length declared by the 2-byte LE suffix (PPF3's suffix is two bytes; PPF2's is four).
-- A trailer is recognized only whole — both markers where the length says they belong —
-- and anything less leaves the body untouched, for the record parser to answer.
splitFileIdTrailer :: EncodingName -> ByteString -> PPF3FileIdSplit
splitFileIdTrailer metadataEncoding recordBody
  | byteLength recordBody < ppf3FileIdFooterLength <> ppf3FileIdLengthFieldWidth = withoutTrailer
  | footerCandidate /= "@END_FILE_ID.DIZ"                                        = withoutTrailer
  | dizContentLength > byteLength bytesBeforeFooter                              = withoutTrailer
  | markerCandidate /= "@BEGIN_FILE_ID.DIZ"                                      = withoutTrailer
  | otherwise = PPF3FileIdSplit
      { ppf3SplitFileId     = Just (PPF3CarriedFileId dizContentBytes dizText (substitutionCount dizNotices))
      , ppf3SplitRecordBody = dropLengthFromEnd trailerSize recordBody
      , ppf3SplitAdvisories =
          [ FileIdDizExceedsFormatCap LabelPPF3 (ActualLength dizContentLength) (MaxLength ppf3FileIdMaxContentLength)
          | dizContentLength > ppf3FileIdMaxContentLength ]
          ++ decodeLossAdvisories LabelPPF3 FieldFileIdDiz dizNotices
      }
  where
    withoutTrailer = PPF3FileIdSplit Nothing recordBody []

    (bytesBeforeLengthField, lengthFieldBytes) = splitSuffixOfLength ppf3FileIdLengthFieldWidth recordBody
    (bytesBeforeFooter, footerCandidate)       = splitSuffixOfLength ppf3FileIdFooterLength bytesBeforeLengthField
    (bytesBeforeContent, dizContentBytes)      = splitSuffixOfLength dizContentLength bytesBeforeFooter
    (_, markerCandidate)                       = splitSuffixOfLength ppf3FileIdMarkerLength bytesBeforeContent
    dizContentLength      = Length (fromIntegral (getWord16LE 0 lengthFieldBytes))
    (dizText, dizNotices) = decodeTextLenient metadataEncoding dizContentBytes
    trailerSize = ppf3FileIdMarkerLength <> dizContentLength
               <> ppf3FileIdFooterLength <> ppf3FileIdLengthFieldWidth
