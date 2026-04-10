{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Create
  ( createBPS
  ) where

import Slap.Binary (putWord32LE, putByuuVarint)
import Slap.Checksum (CRC32(..))
import Slap.FFI (rustyCRC32, rustyBpsDiff)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString

-- | Create a BPS patch using the Rust suffix-array diff engine.
createBPS :: SourceFileContents -> TargetFileContents -> ByteString -> PatchFileContents
createBPS (SourceFileContents original) (TargetFileContents modified) metadata =
  let sourceCRC = rustyCRC32 original
      targetCRC = rustyCRC32 modified
      actionBytes = rustyBpsDiff original modified
      body = byteString "BPS1"
             <> putByuuVarint (fromIntegral (ByteString.length original))
             <> putByuuVarint (fromIntegral (ByteString.length modified))
             <> putByuuVarint (fromIntegral (ByteString.length metadata))
             <> byteString metadata
             <> byteString actionBytes
             <> putWord32LE (unCRC32 sourceCRC)
             <> putWord32LE (unCRC32 targetCRC)
      bodyBytes = LazyByteString.toStrict (toLazyByteString body)
      patchCRC = rustyCRC32 bodyBytes
      patchCRCBytes = LazyByteString.toStrict (toLazyByteString (putWord32LE (unCRC32 patchCRC)))
  in PatchFileContents (bodyBytes <> patchCRCBytes)
