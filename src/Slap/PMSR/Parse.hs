{-# LANGUAGE OverloadedStrings #-}

module Slap.PMSR.Parse
  ( parsePMSR
  , parsePMSRBody
  , parseLoop
  ) where

-- PMSR is the patch format produced by Star Rod (Paper Mario 64 modding tool, Java, big-endian).
-- The layout has no formal spec; the most useful public description we found is a Star Rod Discord message,
-- quoted at https://github.com/Sappharad/MultiPatch/issues/15.

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..), pmsrMagicBytes)
import Slap.Status (SlapError(..), Parsed(..), ByteParserError(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runByteParser, throwByteParserError,
                        getBytes, skip, remaining)
import qualified Slap.ByteParser as ByteParser
import Slap.Measure (Length(..), offsetFromParsed,
                     RequiredLength(..), ActualLength(..), RemainingLength(..),
                     ActualMagic(..), ActionIndex, firstAction, nextAction,
                     byteLength)

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

-- Format: 4 bytes "PMSR" magic, uint32BE record count,
-- then for each record: uint32BE offset, uint32BE length, then data bytes.
parsePMSR :: PatchFileContents -> Either SlapError (Parsed PMSRPatch)
parsePMSR (PatchFileContents input)
  | ByteString.length input < 4 = Left (InputTooShort LabelPMSR (RequiredLength (Length 4)) (ActualLength (byteLength input)))
  | ByteString.take 4 input /= pmsrMagicBytes = Left (BadMagic LabelPMSR (ActualMagic (ByteString.take 4 input)))
  | otherwise = case runByteParser parsePMSRBody input of
      Left parserError -> Left (ParseError LabelPMSR parserError)
      Right result -> Right (Parsed result [])

parsePMSRBody :: ByteParser PMSRPatch
parsePMSRBody = do
  skip (Length 4)  -- magic
  count <- fromIntegral <$> ByteParser.word32BE
  records  <- parseLoop firstAction count []
  pure (PMSRPatch (Vector.fromList records))

parseLoop :: ActionIndex -> Int -> [PMSRRecord] -> ByteParser [PMSRRecord]
parseLoop _ 0 accumulated = pure (reverse accumulated)
parseLoop recordIndex count accumulated = do
  offset <- offsetFromParsed <$> ByteParser.word32BE
  dataLength <- fromIntegral <$> ByteParser.word32BE
  available <- remaining
  if dataLength > unLength available
    then throwByteParserError (ByteParserTruncatedRecord recordIndex
           (RequiredLength (lengthAddingHeader (Length dataLength)))
           (RemainingLength (lengthAddingHeader available)))
    else do
      payload <- getBytes (Length dataLength)
      parseLoop (nextAction recordIndex) (count - 1) (PMSRRecord offset payload : accumulated)
  where
    -- Restate a byte count "as if" the 8-byte record header (4-byte
    -- offset, 4-byte length) had not been consumed yet, so the error
    -- names the whole-record budget.
    lengthAddingHeader :: Length -> Length
    lengthAddingHeader (Length availableAfterHeader) = Length (8 + availableAfterHeader)
