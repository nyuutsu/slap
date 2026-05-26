{-# LANGUAGE OverloadedStrings #-}

module Slap.PMSR.Parse
  ( parsePMSR
  , parsePMSRBody
  , parseLoop
  ) where

-- Canonical reference: Star Rod (Paper Mario 64 modding tool, Java, big-endian)
-- Best available spec: https://github.com/Sappharad/MultiPatch/issues/15 (Star Rod Discord quote)

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..), pmsrMagicBytes)
import Slap.Status (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runByteParser, getBytes, skip, remaining)
import qualified Slap.ByteParser as ByteParser
import Slap.Measure (Length(..), offsetFromParsed,
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     byteLength)

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

-- Format: 4 bytes "PMSR" magic, uint32BE record count,
-- then for each record: uint32BE offset, uint32BE length, then data bytes.
-- Star Rod (Java) uses big-endian — this is the authoritative producer.
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
  records  <- parseLoop count []
  pure (PMSRPatch (Vector.fromList records))

parseLoop :: Int -> [PMSRRecord] -> ByteParser [PMSRRecord]
parseLoop 0 accumulated = pure (reverse accumulated)
parseLoop count accumulated = do
  offset <- offsetFromParsed <$> ByteParser.word32BE
  dataLength <- fromIntegral <$> ByteParser.word32BE
  available <- remaining
  if dataLength > unLength available
    then fail ("record needs " ++ show dataLength ++ " bytes but only "
               ++ show (unLength available) ++ " available")
    else do
      payload <- getBytes (Length dataLength)
      parseLoop (count - 1) (PMSRRecord offset payload : accumulated)
