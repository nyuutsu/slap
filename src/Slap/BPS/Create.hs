{-# LANGUAGE OverloadedStrings #-}

-- | BPS patch creation. The diff itself is computed by the Rust
-- suffix-array engine; this module assembles the wire format around
-- the action stream.
--
-- Wire-format integer safety: the 'fromIntegral' calls in this
-- module convert 'Int' to 'Int64' as required by 'putByuuVarint'.
-- @Int → Int64@ is a no-op on 64-bit hosts (where GHC's 'Int' is
-- 'Int64') and lossless widening on 32-bit; never shrinks.
--
-- 'guardAddressable' is a separate concern, and a spec-fidelity one:
-- the BPS spec permits varints of arbitrary width, naming 128-bit
-- and beyond explicitly. Slap caps both varint values and cursor
-- state at host 'Int' (63-bit signed on 64-bit) — a deliberate
-- slap-side deviation, not a property of the spec. The guard
-- refuses inputs that would require values past the cap, surfacing
-- the deviation at the boundary instead of letting it corrupt
-- later. See @bps/questions.md@ in the slap-format-documentation
-- repository for the deviation rationale.
module Slap.BPS.Create
  ( createBPS
  ) where

import Slap.Binary (putWord32LE, word32LEBytes, putByuuVarint)
import Slap.BPS.Types (bpsMagicBytes)
import Slap.Checksum (CRC32(..))
import Slap.Error (SlapError(..), CreateResult(..))
import Slap.BPS.FFI (bpsDiff)
import Slap.FFI (crc32)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (ActualSize(..), MaxAddressableSize(..), FileSize(..), byteFileSize)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString

-- | Create a BPS patch using the Rust suffix-array diff engine.
-- Rejects inputs larger than the host platform's addressable range,
-- which matters only on 32-bit where 'Int' is 31-bit; on 64-bit the
-- guard is effectively dead (cap is ~9 EB).
createBPS :: InputFileContents -> OutputFileContents -> ByteString
          -> Either SlapError CreateResult
createBPS inputContents@(InputFileContents original) outputContents@(OutputFileContents modified) metadata = do
  guardAddressable (byteFileSize original)
  guardAddressable (byteFileSize modified)
  let sourceCRC = crc32 original
      targetCRC = crc32 modified
      actionBytes = bpsDiff inputContents outputContents
      body = byteString bpsMagicBytes
             <> putByuuVarint (fromIntegral (ByteString.length original))
             <> putByuuVarint (fromIntegral (ByteString.length modified))
             <> putByuuVarint (fromIntegral (ByteString.length metadata))
             <> byteString metadata
             <> byteString actionBytes
             <> putWord32LE (unCRC32 sourceCRC)
             <> putWord32LE (unCRC32 targetCRC)
      bodyBytes = LazyByteString.toStrict (toLazyByteString body)
      patchCRC = crc32 bodyBytes
      patchCRCBytes = word32LEBytes (unCRC32 patchCRC)
  Right (CreateResult (PatchFileContents (bodyBytes <> patchCRCBytes)) [])

-- | The byuu-varint encoder routes lengths through 'Int64', but slap
-- reads sizes as 'Int'; on 32-bit 'Int' is 31-bit-addressable and a
-- file over ~2 GB would silently truncate. Reject at the boundary.
guardAddressable :: FileSize -> Either SlapError ()
guardAddressable size
  | size <= maxAddressable = Right ()
  | otherwise = Left (FileExceedsAddressableRange LabelBPS
                        (ActualSize size)
                        (MaxAddressableSize maxAddressable))
  where
    maxAddressable = FileSize maxBound
