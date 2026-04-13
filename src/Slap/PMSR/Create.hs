{-# LANGUAGE OverloadedStrings #-}

module Slap.PMSR.Create
  ( encodePMSR
  ) where

import Slap.Measure (Offset(..), EncodedHunk(..))
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
    encodeOneRecord (EncodedHunk hunkOffset hunkPayload) =
      word32BE (fromIntegral (unOffset hunkOffset))
      <> word32BE (fromIntegral (ByteString.length hunkPayload))
      <> byteString hunkPayload
