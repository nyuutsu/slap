module Slap.UPS.Apply
  ( applyUPS
  , applyBlocks
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..))
import Slap.Measure (FileSize(..), Delta(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Bits (xor)

-- Caller is responsible for checksum validation.
applyUPS :: UPSPatch -> ByteString -> ByteString
applyUPS patch source =
  let targetSize = fromIntegral (unFileSize (upsTargetSize patch))
      -- Pad or truncate source to target size for XOR
      padded = if ByteString.length source >= targetSize
               then ByteString.take targetSize source
               else source <> ByteString.replicate (targetSize - ByteString.length source) 0
      result = LazyByteString.toStrict $ toLazyByteString $ applyBlocks (upsBlocks patch) padded 0
  in ByteString.take targetSize result

applyBlocks :: [UPSBlock] -> ByteString -> Int -> Builder
applyBlocks [] source position =
  -- Copy remaining source bytes unchanged
  byteString (ByteString.drop position source)
applyBlocks (UPSBlock skipDelta xorBytes : remaining) source position =
  let skipAmount = fromIntegral (unDelta skipDelta)
      skipEnd = position + skipAmount
      -- Copy 'skip' bytes unchanged from source
      unchanged = byteString (ByteString.take skipAmount (ByteString.drop position source))
      -- XOR the patch bytes with source bytes at skipEnd
      xorLength = ByteString.length xorBytes
      xored = ByteString.packZipWith xor (ByteString.take xorLength (ByteString.drop skipEnd source)) xorBytes
      -- Pad if XOR extends beyond source
      extraXor = if skipEnd + xorLength > ByteString.length source
                 then byteString (ByteString.drop (ByteString.length source - skipEnd) xorBytes)
                 else mempty
      -- The terminator position: in the UPS XOR stream, each non-zero run
      -- is followed by a zero (matching byte). Copy it from source unchanged.
      terminatorPosition = skipEnd + xorLength
      terminatorByte = if terminatorPosition < ByteString.length source
                 then byteString (ByteString.singleton (ByteString.index source terminatorPosition))
                 else mempty
  in unchanged <> byteString xored <> extraXor <> terminatorByte
     <> applyBlocks remaining source (terminatorPosition + 1)
