{-# LANGUAGE OverloadedStrings #-}

-- | Parse a PPF1 patch from raw bytes. Spec:
-- @docs/ppf/upstream/pdx-ppf1/ppf-doc.txt@. Reference applier
-- (canonical for the on-wire byte-walk semantics):
-- @docs/ppf/upstream/pdx-ppf1/sources/applyppf.c@.
module Slap.PPF1.Parse (parsePPF1, parsePPF1Records) where

import Slap.PPF1.Types (PPF1Patch(..), PPF1Record(..), PPF1Origin(..),
                        ppf1DescriptionLength)
import Slap.Status (SlapError(..), SlapAdvisory, Parsed(..), ByteParserError(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, throwByteParserError,
                        getByte, getBytes, remaining, skip, word32LE, word32BE)
import Slap.Measure (lengthToInt, Offset, offsetFromParsed, Length(..), EncodingMethodByte(..),
                     ActionIndex,
                     RequiredLength(..), ActualLength(..), RemainingLength(..),
                     firstAction, nextAction, byteLength)
import Slap.Text (EncodedText, EncodingName(..), decodeFixedWidthTextField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

-- | Intermediate result of running the PPF1 body parser,
-- reshaped by 'parsePPF1' into the final 'PPF1Patch' and 'Parsed' envelope.
data PPF1ParsedBody = PPF1ParsedBody
  { ppf1BodyDescription           :: !EncodedText
  , ppf1BodyDescriptionAdvisories :: ![SlapAdvisory]
  , ppf1BodyRecords               :: ![PPF1Record]
  }

parsePPF1 :: PPF1Origin -> EncodingName -> PatchFileContents -> Either SlapError (Parsed PPF1Patch)
parsePPF1 origin metadataEncoding (PatchFileContents input)
  | ByteString.length input < lengthToInt minimumPPF1ParseLength =
      Left (InputTooShort LabelPPF1
              (RequiredLength minimumPPF1ParseLength)
              (ActualLength (byteLength input)))
  | otherwise = do
      () <- checkEncodingByte input
      body <- runFormatParser LabelPPF1 parsePPF1Body input
      pure (Parsed
        PPF1Patch
          { ppf1Description = ppf1BodyDescription body
          , ppf1Records     = ppf1BodyRecords body
          }
        (ppf1BodyDescriptionAdvisories body))
  where
    parsePPF1Body :: ByteParser PPF1ParsedBody
    parsePPF1Body = do
      skip (Length 6)                            -- magic + version + encoding byte
      descriptionBytes <- getBytes ppf1DescriptionLength
      let (descriptionText, descriptionAdvisories) =
            decodeFixedWidthTextField metadataEncoding LabelPPF1 FieldDescription descriptionBytes
      records <- parsePPF1Records origin firstAction
      pure PPF1ParsedBody
        { ppf1BodyDescription           = descriptionText
        , ppf1BodyDescriptionAdvisories = descriptionAdvisories
        , ppf1BodyRecords               = records
        }

-- | The PPF1 header must be readable before we can index byte 5
-- for the encoding-byte check; six bytes is enough for that.
minimumPPF1ParseLength :: Length
minimumPPF1ParseLength = Length 6

-- | Verify the encoding-method byte at offset 5 is @0x00@ (the only
-- value PPF1 defines).
checkEncodingByte :: ByteString -> Either SlapError ()
checkEncodingByte input
  | actual == 0x00 = Right ()
  | otherwise      = Left (UnsupportedEncodingMethod LabelPPF1 (EncodingMethodByte actual))
  where actual = ByteString.index input 5

-- | Parse the PPF1 record stream until input is exhausted, expanding
-- the count=0 RLE-mode records into flat literal payloads as we go.
-- Per spec @ppf-doc.txt@:
--
-- > If parameter 'y' is set to zero (0) then parameter 'z' will be
-- > a two (2) byte field. Byte zero (0) will be the data and byte
-- > one (1) will be the number of repetitions.
--
-- The reference applier (@applyppf.c@, fillout-mode branch)
-- implements this; the reference creator (@makeppf.c@) never emits
-- it. Other PPF1 producers can.
parsePPF1Records :: PPF1Origin -> ActionIndex -> ByteParser [PPF1Record]
parsePPF1Records origin = parseRemainingRecords
  where
    readOffsetWord = case origin of
      PPF1OriginPC    -> word32LE
      PPF1OriginAmiga -> word32BE
    parseRemainingRecords recordIndex = do
      remainingBytes <- remaining
      if unLength remainingBytes < 5 then pure []
      else do
        recordOffset <- offsetFromParsed <$> readOffsetWord
        countByte <- fromIntegral <$> getByte
        remainingAfterHeader <- remaining
        record <- if countByte == 0
          then parseRleBody recordIndex remainingAfterHeader recordOffset
          else parseLiteralBody recordIndex remainingAfterHeader recordOffset countByte
        rest <- parseRemainingRecords (nextAction recordIndex)
        pure (record : rest)
    parseLiteralBody :: ActionIndex -> Length -> Offset -> Int -> ByteParser PPF1Record
    parseLiteralBody recordIndex remainingAfterHeader writeOffset payloadLength
      | unLength remainingAfterHeader < fromIntegral payloadLength =
          throwByteParserError (ByteParserTruncatedRecord recordIndex
            (RequiredLength (Length (5 + fromIntegral payloadLength)))
            (RemainingLength (lengthWithRecordHeader remainingAfterHeader)))
      | otherwise = do
          payload <- getBytes (Length (fromIntegral payloadLength))
          pure (PPF1Record writeOffset payload)

    parseRleBody :: ActionIndex -> Length -> Offset -> ByteParser PPF1Record
    parseRleBody recordIndex remainingAfterHeader writeOffset
      | unLength remainingAfterHeader < 2 =
          throwByteParserError (ByteParserTruncatedRecord recordIndex
            (RequiredLength (Length 7))
            (RemainingLength (lengthWithRecordHeader remainingAfterHeader)))
      | otherwise = do
          dataByte <- getByte
          repeatCount <- fromIntegral <$> getByte
          pure (PPF1Record writeOffset (ByteString.replicate repeatCount dataByte))

    -- Add the consumed 5-byte header back so the truncation error's RemainingLength names the whole-record budget, matching RequiredLength.
    lengthWithRecordHeader :: Length -> Length
    lengthWithRecordHeader (Length availableAfterHeader) = Length (5 + availableAfterHeader)


