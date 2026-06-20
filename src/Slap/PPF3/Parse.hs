{-# LANGUAGE OverloadedStrings #-}

-- | Parse a PPF3 patch from raw bytes. Spec:
-- @docs/ppf/upstream/ppf-master/ppfdev/PPF3.txt@. Reference applier
-- (canonical for the on-wire byte-walk semantics):
-- @docs/ppf/upstream/ppf-master/ppfdev/applyppf_src/applyppf3_linux.c@.
module Slap.PPF3.Parse (parsePPF3, parsePPF3Records) where

import Slap.PPF3.Types (PPF3Patch(..), PPF3Record(..),
                        PPF3ImageType(..), PPF3ValidationBlock(..),
                        PPF3FileId, ppf3FileIdFromParsed,
                        ppf3DescriptionLength, ppf3MinHeaderLength,
                        ppf3ValidationSize,
                        ppf3FileIdLengthFieldWidth,
                        ppf3FileIdMarkerLength, ppf3FileIdFooterLength)
import Slap.Binary (getWord16LE)
import Slap.Status (SlapError(..), SlapAdvisory, Parsed(..), ByteParserError(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runByteParser, throwByteParserError,
                        getByte, getBytes, remaining, skip, int64LE)
import Slap.Measure (offsetFromParsed, Length(..), EncodingMethodByte(..),
                     RawFlagByte(..),
                     ActionIndex,
                     RequiredLength(..), ActualLength(..), RemainingLength(..),
                     firstAction, nextAction, byteLength)
import Slap.Text (EncodedText, EncodingName(..),
                  decodeTextLenient, decodeLossAdvisories,
                  decodeFixedWidthTextField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bifunctor (first)
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
  | ByteString.length input < unLength minimumPPF3ParseLength =
      Left (InputTooShort LabelPPF3
              (RequiredLength minimumPPF3ParseLength)
              (ActualLength (byteLength input)))
  | otherwise = do
      () <- checkEncodingByte input
      header <- first (ParseError LabelPPF3) (runByteParser parseHeader input)
      imageType <- case ppf3HeaderImageTypeByte header of
        0x00 -> Right BIN
        0x01 -> Right GI
        byte -> Left (UnknownFlag LabelPPF3 FieldImageType (RawFlagByte byte))
      let headerLength = if ppf3HeaderHasBlockCheck header
                           then ppf3MinHeaderLength <> ppf3ValidationSize
                           else ppf3MinHeaderLength
          (detectedFileId, fileIdAdvisories) = detectFileId metadataEncoding input
          fileId     = fmap fst detectedFileId
          recordBody = stripFileId detectedFileId
                            (ByteString.drop (unLength headerLength) input)
      records <- first (ParseError LabelPPF3)
                       (runByteParser (parsePPF3Records (ppf3HeaderHasUndo header) firstAction)
                                      recordBody)
      pure (Parsed
        PPF3Patch
          { ppf3Description     = ppf3HeaderDescription header
          , ppf3ImageType       = imageType
          , ppf3HasUndo         = ppf3HeaderHasUndo header
          , ppf3ValidationBlock = ppf3HeaderValidationBlock header
          , ppf3Records         = records
          , ppf3FileId          = fileId
          }
        (ppf3HeaderDescriptionAdvisories header ++ fileIdAdvisories))
  where
    parseHeader :: ByteParser PPF3ParsedHeader
    parseHeader = do
      skip (Length 6)
      descriptionBytes <- getBytes ppf3DescriptionLength
      let (descriptionText, descriptionAdvisories) =
            decodeFixedWidthTextField metadataEncoding LabelPPF3 FieldDescription descriptionBytes
      imageTypeByte <- getByte
      hasBlockByte <- getByte
      hasUndoByte <- getByte
      skip (Length 1)
      validationBlock <- if hasBlockByte /= 0
        then Just . PPF3ValidationBlock <$> getBytes ppf3ValidationSize
        else pure Nothing
      pure PPF3ParsedHeader
        { ppf3HeaderDescription           = descriptionText
        , ppf3HeaderDescriptionAdvisories = descriptionAdvisories
        , ppf3HeaderImageTypeByte         = imageTypeByte
        , ppf3HeaderHasBlockCheck         = hasBlockByte /= 0
        , ppf3HeaderHasUndo               = hasUndoByte /= 0
        , ppf3HeaderValidationBlock       = validationBlock
        }

minimumPPF3ParseLength :: Length
minimumPPF3ParseLength = Length 6

-- | Verify the encoding-method byte at offset 5 is @0x02@.
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
  if unLength remainingBytes < 9 then pure []
  else do
    recordOffset <- offsetFromParsed <$> int64LE
    payloadLength <- fromIntegral <$> getByte
    let totalNeeded = 9 + payloadLength + (if hasUndo then payloadLength else 0)
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
-- FILE_ID.DIZ trailer detection (PPF3-specific 2-byte length field)
----------------------------------------------------------------------------

-- | Look at the end of the patch for a FILE_ID.DIZ trailer; PPF3's
-- length suffix is two bytes (vs PPF2's four). Returns both the
-- typed FILE_ID.DIZ and the inner-content byte count as declared on
-- the wire (alongside any decode advisories). The byte count is
-- plumbed back to 'stripFileId' so the body-trim doesn't have to
-- re-encode the typed text just to recover the on-wire size.
detectFileId :: EncodingName -> ByteString -> (Maybe (PPF3FileId, Int), [SlapAdvisory])
detectFileId metadataEncoding input
  | ByteString.length input < markerSize + lengthFieldSize = (Nothing, [])
  | ByteString.take markerSize trailerCandidate /= "@END_FILE_ID.DIZ" = (Nothing, [])
  | otherwise =
      let dizContentLength = fromIntegral (getWord16LE
                              (ByteString.length input - lengthFieldSize) input)
          dizContentEnd    = ByteString.length input - lengthFieldSize - markerSize
          dizContentStart  = dizContentEnd - dizContentLength
      in if dizContentStart < 0 then (Nothing, [])
         else let dizContentBytes = ByteString.take dizContentLength
                                      (ByteString.drop dizContentStart input)
                  (dizText, dizNotices) = decodeTextLenient metadataEncoding dizContentBytes
                  dizAdvisories = decodeLossAdvisories LabelPPF3 FieldFileIdDiz dizNotices
              in (Just (ppf3FileIdFromParsed dizText, dizContentLength), dizAdvisories)
  where
    markerSize       = unLength ppf3FileIdFooterLength
    lengthFieldSize  = unLength ppf3FileIdLengthFieldWidth
    trailerCandidate = ByteString.drop (ByteString.length input - lengthFieldSize - markerSize)
                         (ByteString.take (ByteString.length input - lengthFieldSize) input)

stripFileId :: Maybe (PPF3FileId, Int) -> ByteString -> ByteString
stripFileId Nothing body = body
stripFileId (Just (_, contentByteCount)) body =
  let trailerSize = unLength ppf3FileIdMarkerLength
                  + contentByteCount
                  + unLength ppf3FileIdFooterLength
                  + unLength ppf3FileIdLengthFieldWidth
  in ByteString.take (ByteString.length body - trailerSize) body
