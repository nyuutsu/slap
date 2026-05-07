{-# LANGUAGE OverloadedStrings #-}

module Slap.PMSR.Create
  ( encodePMSR
  ) where

import Slap.Measure (Offset(..))
import Slap.Narrow (EncodedHunk, encodedOffset, encodedPayload)
import Slap.PMSR.Types (pmsrMagicBytes)
import Slap.FileContents (PatchFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString

encodePMSR :: [EncodedHunk] -> PatchFileContents
encodePMSR records = PatchFileContents $ LazyByteString.toStrict $ toLazyByteString $
    byteString pmsrMagicBytes
    <> word32BE (fromIntegral (length records))
    <> foldMap encodeOneRecord records
  where
    encodeOneRecord ehunk =
      let recordOffset  = encodedOffset ehunk
          recordPayload = encodedPayload ehunk
      in word32BE (fromIntegral (unOffset recordOffset))
         <> word32BE (fromIntegral (ByteString.length recordPayload))
         <> byteString recordPayload
