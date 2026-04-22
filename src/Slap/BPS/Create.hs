{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Create
  ( createBPS
  ) where

import Slap.Binary (putWord32LE, putByuuVarint)
import Slap.BPS.Types (bpsMagicBytes)
import Slap.Checksum (CRC32(..))
import Slap.Error (SlapError(..), CreateResult(..))
import Slap.FFI (rustyCRC32, rustyBpsDiff)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (ActualSize(..), MaxAddressableSize(..), FileSize(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString

-- | Create a BPS patch using the Rust suffix-array diff engine.
-- Rejects inputs larger than the host platform's addressable range,
-- which matters only on 32-bit where 'Int' is 31-bit; on 64-bit the
-- guard is effectively dead (cap is ~9 EB).
createBPS :: SourceFileContents -> TargetFileContents -> ByteString
          -> Either SlapError CreateResult
createBPS (SourceFileContents original) (TargetFileContents modified) metadata = do
  guardAddressable (ByteString.length original)
  guardAddressable (ByteString.length modified)
  let sourceCRC = rustyCRC32 original
      targetCRC = rustyCRC32 modified
      actionBytes = rustyBpsDiff original modified
      body = byteString bpsMagicBytes
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
  Right (CreateResult (PatchFileContents (bodyBytes <> patchCRCBytes)) [])

-- | The byuu-varint encoder routes lengths through 'Int64', but slap
-- reads sizes as 'Int'; on 32-bit 'Int' is 31-bit-addressable and a
-- file over ~2 GB would silently truncate. Reject at the boundary.
guardAddressable :: Int -> Either SlapError ()
guardAddressable size
  | size <= unFileSize maxAddressable = Right ()
  | otherwise = Left (FileExceedsAddressableRange LabelBPS
                        (ActualSize (FileSize size))
                        (MaxAddressableSize maxAddressable))
  where
    maxAddressable = FileSize maxBound
