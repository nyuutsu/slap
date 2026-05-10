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
                        PPF2FileId, unPPF2FileId, ppf2FileIdFromParsed,
                        PPF2SourceSize, ppf2SourceSizeFromParsed,
                        ppf2DescriptionLength, ppf2HeaderLength,
                        ppf2ValidationSize,
                        ppf2FileIdLengthFieldWidth,
                        ppf2FileIdMarkerLength, ppf2FileIdFooterLength)
import Slap.Binary (getWord32LE)
import Slap.Error (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, remaining, skip, word32LE)
import Slap.Measure (Offset(..), Length(..),
                     EncodingMethodByte(..),
                     ActionIndex, unActionIndex,
                     RequiredLength(..), ActualLength(..),
                     firstAction, nextAction)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bifunctor (first)

parsePPF2 :: PatchFileContents -> Either SlapError (Parsed PPF2Patch)
parsePPF2 (PatchFileContents input)
  | ByteString.length input < unLength minimumPPF2ParseLength =
      Left (InputTooShort LabelPPF2
              (RequiredLength minimumPPF2ParseLength)
              (ActualLength (Length (ByteString.length input))))
  | otherwise = do
      () <- checkEncodingByte input
      let fileId     = detectFileId input
          recordBody = stripFileId fileId
                          (ByteString.drop (unLength ppf2HeaderLength) input)
      (description, fileSize, validationBlock) <-
        first (ParseError LabelPPF2) (runGet parsePPF2Header input)
      records <- first (ParseError LabelPPF2)
                       (runGet (parsePPF2Records firstAction) recordBody)
      pure (Parsed
        PPF2Patch
          { ppf2Description     = description
          , ppf2SourceFileSize  = fileSize
          , ppf2ValidationBlock = validationBlock
          , ppf2Records         = records
          , ppf2FileId          = fileId
          }
        [])
  where
    parsePPF2Header :: Get (ByteString, PPF2SourceSize, PPF2ValidationBlock)
    parsePPF2Header = do
      skip (Length 6)
      description <- getBytes ppf2DescriptionLength
      fileSize <- ppf2SourceSizeFromParsed <$> word32LE
      validationBlock <- PPF2ValidationBlock <$> getBytes ppf2ValidationSize
      pure (description, fileSize, validationBlock)

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

-- | Same record-stream shape as PPF1: @parsePPF1Records@ and
-- @parsePPF2Records@ are deliberately separate so each format owns
-- its own copy. Pulling them into a shared helper would invite a
-- single-edit, two-format mistake whenever a producer-quirk for one
-- version turns up that doesn't apply to the other.
parsePPF2Records :: ActionIndex -> Get [PPF2Record]
parsePPF2Records recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 5 then pure []
  else do
    recordOffset <- Offset . fromIntegral <$> word32LE
    countByte <- fromIntegral <$> getByte
    remainingAfterHeader <- remaining
    record <- if countByte == 0
      then parseRleBody recordIndex remainingAfterHeader recordOffset
      else parseLiteralBody recordIndex remainingAfterHeader recordOffset countByte
    rest <- parsePPF2Records (nextAction recordIndex)
    pure (record : rest)
  where
    parseLiteralBody :: ActionIndex -> Length -> Offset -> Int -> Get PPF2Record
    parseLiteralBody index remainingAfterHeader writeOffset payloadLength
      | unLength remainingAfterHeader < payloadLength =
          fail (truncatedMessage index
                                 (RequiredLength (Length (5 + payloadLength)))
                                 (ActualLength (lengthAddingHeader remainingAfterHeader)))
      | otherwise = do
          payload <- getBytes (Length payloadLength)
          pure (PPF2Record writeOffset payload)

    parseRleBody :: ActionIndex -> Length -> Offset -> Get PPF2Record
    parseRleBody index remainingAfterHeader writeOffset
      | unLength remainingAfterHeader < 2 =
          fail (truncatedMessage index
                                 (RequiredLength (Length 7))
                                 (ActualLength (lengthAddingHeader remainingAfterHeader)))
      | otherwise = do
          dataByte <- getByte
          repeatCount <- fromIntegral <$> getByte
          pure (PPF2Record writeOffset (ByteString.replicate repeatCount dataByte))

    lengthAddingHeader :: Length -> Length
    lengthAddingHeader (Length availableAfterHeader) = Length (5 + availableAfterHeader)

truncatedMessage :: ActionIndex -> RequiredLength -> ActualLength -> String
truncatedMessage recordIndex
                 (RequiredLength (Length needed))
                 (ActualLength   (Length available)) =
  "record " ++ show (unActionIndex recordIndex)
  ++ " truncated (need " ++ show needed ++ " bytes, " ++ show available ++ " available)"

----------------------------------------------------------------------------
-- FILE_ID.DIZ trailer detection (PPF2-specific 4-byte length field)
----------------------------------------------------------------------------

-- | Look at the very end of the patch for a FILE_ID.DIZ trailer.
-- The wire shape is:
--
-- @\"\@BEGIN_FILE_ID.DIZ\" <content> \"\@END_FILE_ID.DIZ\" <length:LE32>@
--
-- with the @<length>@ four bytes naming the @<content>@ length and
-- letting us walk backwards to find the start. Returns 'Nothing' if
-- the @\"\@END_FILE_ID.DIZ\"@ marker isn't where the length suffix
-- says it should be.
detectFileId :: ByteString -> Maybe PPF2FileId
detectFileId input
  | ByteString.length input < markerSize + lengthFieldSize = Nothing
  | ByteString.take markerSize trailerCandidate /= "@END_FILE_ID.DIZ" = Nothing
  | otherwise =
      let dizContentLength = fromIntegral (getWord32LE
                              (ByteString.length input - lengthFieldSize) input)
          dizContentEnd    = ByteString.length input - lengthFieldSize - markerSize
          dizContentStart  = dizContentEnd - dizContentLength
      in if dizContentStart < 0 then Nothing
         else Just (ppf2FileIdFromParsed (ByteString.take dizContentLength
                                  (ByteString.drop dizContentStart input)))
  where
    markerSize        = unLength ppf2FileIdFooterLength
    lengthFieldSize   = unLength ppf2FileIdLengthFieldWidth
    trailerCandidate  = ByteString.drop (ByteString.length input - lengthFieldSize - markerSize)
                          (ByteString.take (ByteString.length input - lengthFieldSize) input)

-- | Trim the FILE_ID.DIZ trailer off the record body, if one was
-- detected. Leaves the body unchanged otherwise.
stripFileId :: Maybe PPF2FileId -> ByteString -> ByteString
stripFileId Nothing body = body
stripFileId (Just fid) body =
  let content = unPPF2FileId fid
      trailerSize = unLength ppf2FileIdMarkerLength
                  + ByteString.length content
                  + unLength ppf2FileIdFooterLength
                  + unLength ppf2FileIdLengthFieldWidth
  in ByteString.take (ByteString.length body - trailerSize) body
