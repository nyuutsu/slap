{-# LANGUAGE OverloadedStrings #-}

-- | Parse a PPF1 patch from raw bytes. Spec:
-- @docs/ppf/upstream/pdx-ppf1/ppf-doc.txt@. Reference applier
-- (canonical for the on-wire byte-walk semantics):
-- @docs/ppf/upstream/pdx-ppf1/sources/applyppf.c@.
module Slap.PPF1.Parse (parsePPF1, parsePPF1Records) where

import Slap.PPF1.Types (PPF1Patch(..), PPF1Record(..),
                        ppf1DescriptionLength)
import Slap.Error (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, remaining, skip, word32LE)
import Slap.Measure (Offset(..), Length(..), EncodingMethodByte(..),
                     ActionIndex, unActionIndex,
                     RequiredLength(..), ActualLength(..),
                     firstAction, nextAction)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bifunctor (first)

parsePPF1 :: PatchFileContents -> Either SlapError (Parsed PPF1Patch)
parsePPF1 (PatchFileContents input)
  | ByteString.length input < unLength minimumPPF1ParseLength =
      Left (InputTooShort LabelPPF1
              (RequiredLength minimumPPF1ParseLength)
              (ActualLength (Length (ByteString.length input))))
  | otherwise = do
      () <- checkEncodingByte input
      patch <- first (ParseError LabelPPF1) (runGet parsePPF1Body input)
      pure (Parsed patch [])
  where
    parsePPF1Body :: Get PPF1Patch
    parsePPF1Body = do
      skip (Length 6)                            -- magic + version + encoding byte
      description <- getBytes ppf1DescriptionLength
      records <- parsePPF1Records firstAction
      pure PPF1Patch
        { ppf1Description = description
        , ppf1Records     = records
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
parsePPF1Records :: ActionIndex -> Get [PPF1Record]
parsePPF1Records recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 5 then pure []
  else do
    recordOffset <- Offset . fromIntegral <$> word32LE
    countByte <- fromIntegral <$> getByte
    remainingAfterHeader <- remaining
    record <- if countByte == 0
      then parseRleBody recordIndex remainingAfterHeader recordOffset
      else parseLiteralBody recordIndex remainingAfterHeader recordOffset countByte
    rest <- parsePPF1Records (nextAction recordIndex)
    pure (record : rest)
  where
    parseLiteralBody :: ActionIndex -> Length -> Offset -> Int -> Get PPF1Record
    parseLiteralBody index remainingAfterHeader writeOffset payloadLength
      | unLength remainingAfterHeader < payloadLength =
          fail (truncatedMessage index
                                 (RequiredLength (Length (5 + payloadLength)))
                                 (ActualLength (lengthAddingHeader remainingAfterHeader)))
      | otherwise = do
          payload <- getBytes (Length payloadLength)
          pure (PPF1Record writeOffset payload)

    parseRleBody :: ActionIndex -> Length -> Offset -> Get PPF1Record
    parseRleBody index remainingAfterHeader writeOffset
      | unLength remainingAfterHeader < 2 =
          fail (truncatedMessage index
                                 (RequiredLength (Length 7))
                                 (ActualLength (lengthAddingHeader remainingAfterHeader)))
      | otherwise = do
          dataByte <- getByte
          repeatCount <- fromIntegral <$> getByte
          pure (PPF1Record writeOffset (ByteString.replicate repeatCount dataByte))

    -- Restate the byte count "as if" we hadn't consumed the 5-byte
    -- record header yet, for error messages that name the whole-
    -- record budget.
    lengthAddingHeader :: Length -> Length
    lengthAddingHeader (Length availableAfterHeader) = Length (5 + availableAfterHeader)

-- | Format a truncated-record error message.
truncatedMessage :: ActionIndex -> RequiredLength -> ActualLength -> String
truncatedMessage recordIndex
                 (RequiredLength (Length needed))
                 (ActualLength   (Length available)) =
  "record " ++ show (unActionIndex recordIndex)
  ++ " truncated (need " ++ show needed ++ " bytes, " ++ show available ++ " available)"

