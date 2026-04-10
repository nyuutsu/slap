{-# LANGUAGE OverloadedStrings #-}

module Slap.PMSR.Parse
  ( parsePMSR
  , parsePMSRBody
  , parseLoop
  ) where

-- Canonical reference: Star Rod (Paper Mario 64 modding tool, Java, big-endian)
-- Best available spec: https://github.com/Sappharad/MultiPatch/issues/15 (Star Rod Discord quote)

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..))
import Slap.Error (SlapError(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getBytes, skip, remaining)
import qualified Slap.Get as Get
import Slap.Measure (Length(..), Offset(..),
                     RequiredLength(..), ActualLength(..), ActualMagic(..))

import qualified Data.ByteString as ByteString

-- Format: 4 bytes "PMSR" magic, uint32BE record count,
-- then for each record: uint32BE offset, uint32BE length, then data bytes.
-- Star Rod (Java) uses big-endian — this is the authoritative producer.
parsePMSR :: PatchFileContents -> Either SlapError PMSRPatch
parsePMSR (PatchFileContents input)
  | ByteString.length input < 4 = Left (InputTooShort LabelPMSR (RequiredLength (Length 4)) (ActualLength (Length (ByteString.length input))))
  | ByteString.take 4 input /= "PMSR" = Left (BadMagic LabelPMSR (ActualMagic (ByteString.take 4 input)))
  | otherwise = case runGet parsePMSRBody input of
      Left errorMessage -> Left (ParseError LabelPMSR errorMessage)
      Right result -> Right result

parsePMSRBody :: Get PMSRPatch
parsePMSRBody = do
  skip (Length 4)  -- magic
  count <- fromIntegral <$> Get.word32BE
  records  <- parseLoop count []
  pure (PMSRPatch records)

parseLoop :: Int -> [PMSRRecord] -> Get [PMSRRecord]
parseLoop 0 accumulated = pure (reverse accumulated)
parseLoop count accumulated = do
  offset <- Offset . fromIntegral <$> Get.word32BE
  dataLength <- fromIntegral <$> Get.word32BE
  available <- remaining
  if dataLength > unLength available
    then fail ("record needs " ++ show dataLength ++ " bytes but only "
               ++ show (unLength available) ++ " available")
    else do
      payload <- getBytes (Length dataLength)
      parseLoop (count - 1) (PMSRRecord offset payload : accumulated)
