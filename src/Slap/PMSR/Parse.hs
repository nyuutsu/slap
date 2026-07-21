{-# LANGUAGE OverloadedStrings #-}

module Slap.PMSR.Parse
  ( parsePMSR
  , parsePMSRBody
  , parseRecordStream
  ) where

-- PMSR is the patch format produced by Star Rod (Paper Mario 64 modding tool, Java, big-endian).
-- The layout has no formal spec; the most useful public description we found is a Star Rod Discord message,
-- quoted at https://github.com/Sappharad/MultiPatch/issues/15.

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..), pmsrMagicBytes)
import Slap.Status (SlapError(..), SlapAdvisory(..), Parsed(..), ByteParserError(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, throwByteParserError,
                        getBytes, skip, remaining)
import qualified Slap.ByteParser as ByteParser
import Slap.Measure (Length(..), Offset(..), offsetFromParsed,
                     RequiredLength(..), ActualLength(..), RemainingLength(..),
                     ActualMagic(..), ActionIndex, firstAction, nextAction,
                     byteLength)

import Control.Monad (when)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.Foldable (traverse_)

-- Format: 4 bytes "PMSR" magic, then a record count, then for each record an offset, a length, and that many data bytes.
-- Star Rod lays all three numbers down with @ByteBuffer.putInt@, so each is a Java @int@: signed, four bytes, big-endian.
-- The offset is read as one here; a negative reaches no further than 'rejectNegativeRecordOffsets', the apply walk
-- writing through a raw pointer that has no answer for a position behind the buffer.
parsePMSR :: PatchFileContents -> Either SlapError (Parsed PMSRPatch)
parsePMSR (PatchFileContents input)
  | ByteString.length input < 4 = Left (InputTooShort LabelPMSR (RequiredLength (Length 4)) (ActualLength (byteLength input)))
  | ByteString.take 4 input /= pmsrMagicBytes = Left (BadMagic LabelPMSR (ActualMagic (ByteString.take 4 input)))
  | otherwise = do
      (patch, advisories) <- runFormatParser LabelPMSR parsePMSRBody input
      rejectNegativeRecordOffsets patch
      Right (Parsed patch advisories)

parsePMSRBody :: ByteParser (PMSRPatch, [SlapAdvisory])
parsePMSRBody = do
  skip (Length 4)  -- magic
  count    <- fromIntegral <$> ByteParser.word32BE
  records  <- parseRecordStream firstAction count []
  leftover <- remaining
  pure ( PMSRPatch (Vector.fromList records)
       , [PMSRTrailingBytes leftover | leftover > Length 0] )

parseRecordStream :: ActionIndex -> Int -> [PMSRRecord] -> ByteParser [PMSRRecord]
parseRecordStream _ 0 accumulated = pure (reverse accumulated)
parseRecordStream recordIndex count accumulated = do
  offset <- offsetFromParsed <$> ByteParser.int32BE
  dataLength <- fromIntegral <$> ByteParser.word32BE
  available <- remaining
  when (dataLength > unLength available) $
    throwByteParserError (ByteParserTruncatedRecord recordIndex
      (RequiredLength (lengthWithRecordHeader (Length dataLength)))
      (RemainingLength (lengthWithRecordHeader available)))
  payload <- getBytes (Length dataLength)
  parseRecordStream (nextAction recordIndex) (count - 1) (PMSRRecord offset payload : accumulated)
  where
    -- Restate a byte count "as if" the 8-byte record header (4-byte
    -- offset, 4-byte length) had not been consumed yet, so the error
    -- names the whole-record budget.
    lengthWithRecordHeader :: Length -> Length
    lengthWithRecordHeader (Length availableAfterHeader) = Length (8 + availableAfterHeader)

-- | A record offset the signed field admits but no buffer has room for.
-- The count and the payload length are answered where they are used: a nonsensical count runs the record walk past the
-- end of the input, and a negative length reaches 'getBytes', which refuses one itself.
rejectNegativeRecordOffsets :: PMSRPatch -> Either SlapError ()
rejectNegativeRecordOffsets patch =
  traverse_ refuseNegativeOffset (zip (iterate nextAction firstAction) (Vector.toList (pmsrRecords patch)))
  where
    refuseNegativeOffset (actionIndex, record)
      | unOffset (pmsrOffset record) < 0 =
          Left (NegativeRecordOffset LabelPMSR actionIndex (pmsrOffset record))
      | otherwise = Right ()
