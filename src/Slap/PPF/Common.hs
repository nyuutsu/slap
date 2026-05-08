{-# LANGUAGE OverloadedStrings #-}

-- | Scaffolding shared by the PPF1, PPF2, and PPF3 parsers. PPF4
-- shares none of this machinery and does not import this module.
module Slap.PPF.Common
  ( wrapError
  , checkPPF1Encoding
  , checkPPF2Encoding
  , checkPPF3Encoding
  , parseRecords32
  , detectFileId
  , stripFileId
  , truncatedMessage
  ) where

import Slap.PPF.Types (PPFRecord(..),
                       PPFFileId(..),
                       fileIdMarkerLength, fileIdFooterLength)
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, getByte, getBytes, remaining, word32LE)
import Slap.Measure (Offset(..), Length(..), EncodingMethodByte(..),
                     ActionIndex(unActionIndex), RequiredLength(..), ActualLength(..),
                     nextAction)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

-- | Wrap a Get error string into a SlapError.
wrapError :: FormatLabel -> Either String a -> Either SlapError a
wrapError label = either (Left . ParseError label) Right

-- | Byte 5 of a PPF header: encoding method. PPF1 expects 0x00,
-- PPF2 expects 0x01, PPF3 expects 0x02. PPF4 has no encoding-byte
-- check and does not call any of these helpers.

checkPPF1Encoding :: ByteString -> Either SlapError ()
checkPPF1Encoding input
  | actual == 0x00 = Right ()
  | otherwise      = Left (UnsupportedEncodingMethod LabelPPF1 (EncodingMethodByte actual))
  where actual = ByteString.index input 5

checkPPF2Encoding :: ByteString -> Either SlapError ()
checkPPF2Encoding input
  | actual == 0x01 = Right ()
  | otherwise      = Left (UnsupportedEncodingMethod LabelPPF2 (EncodingMethodByte actual))
  where actual = ByteString.index input 5

checkPPF3Encoding :: ByteString -> Either SlapError ()
checkPPF3Encoding input
  | actual == 0x02 = Right ()
  | otherwise      = Left (UnsupportedEncodingMethod LabelPPF3 (EncodingMethodByte actual))
  where actual = ByteString.index input 5

-- | Parse PPF1/PPF2 records (4-byte offset, 1-byte count, N bytes data).
parseRecords32 :: FormatLabel -> ActionIndex -> Get [PPFRecord]
parseRecords32 label recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 5 then pure []
  else do
    recordOffset <- Offset . fromIntegral <$> word32LE
    count <- fromIntegral <$> getByte
    remainingAfterHeader <- remaining
    if unLength remainingAfterHeader < count
      then fail (truncatedMessage recordIndex
                                  (RequiredLength (Length (5 + count)))
                                  (ActualLength remainingBytes))
      else do
        payload <- getBytes (Length count)
        rest <- parseRecords32 label (nextAction recordIndex)
        pure (PPFRecord recordOffset payload Nothing : rest)

-- | File_ID.diz detection, parameterised by length-field reader and width.
detectFileId :: (Integral a) => (Int -> ByteString -> a) -> Int -> ByteString -> Maybe PPFFileId
detectFileId readLength lengthSize input
  | ByteString.length input < 4 + lengthSize = Nothing
  | ByteString.take 4 (ByteString.drop (ByteString.length input - 4 - lengthSize) input) == ".DIZ" =
      let idLength    = fromIntegral (readLength (ByteString.length input - lengthSize) input)
          trailerSize = unLength (fileIdMarkerLength
                                  <> Length idLength
                                  <> fileIdFooterLength
                                  <> Length lengthSize)
      in Just (PPFFileId (ByteString.take idLength (ByteString.drop (ByteString.length input - trailerSize + unLength fileIdMarkerLength) input)))
  | otherwise = Nothing

-- | Strip File_ID.diz trailer bytes from the record body.
stripFileId :: Int -> Maybe PPFFileId -> ByteString -> ByteString
stripFileId _ Nothing body = body
stripFileId lengthSize (Just (PPFFileId content)) body =
  let trimmed = unLength (fileIdMarkerLength
                          <> Length (ByteString.length content)
                          <> fileIdFooterLength
                          <> Length lengthSize)
  in ByteString.take (ByteString.length body - trimmed) body

-- | Format a truncated-record error message.
truncatedMessage :: ActionIndex -> RequiredLength -> ActualLength -> String
truncatedMessage recordIndex
                 (RequiredLength (Length needed))
                 (ActualLength   (Length available)) =
  "record " ++ show (unActionIndex recordIndex)
  ++ " truncated (need " ++ show needed ++ " bytes, " ++ show available ++ " available)"
