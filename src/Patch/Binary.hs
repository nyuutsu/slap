module Patch.Binary
  ( -- * Little-endian readers
    getWord16LE
  , getWord32LE
  , getInt64LE
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Bits (shiftL, (.|.))
import Data.Int (Int64)
import Data.Word (Word16, Word32)

----------------------------------------------------------------------------
-- Little-endian readers
----------------------------------------------------------------------------

getWord16LE :: Int -> ByteString -> Word16
getWord16LE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Word16
  in b 0 .|. (b 1 `shiftL` 8)

getWord32LE :: Int -> ByteString -> Word32
getWord32LE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Word32
  in b 0 .|. (b 1 `shiftL` 8) .|. (b 2 `shiftL` 16) .|. (b 3 `shiftL` 24)

getInt64LE :: Int -> ByteString -> Int64
getInt64LE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Int64
  in b 0 .|. (b 1 `shiftL` 8) .|. (b 2 `shiftL` 16) .|. (b 3 `shiftL` 24)
     .|. (b 4 `shiftL` 32) .|. (b 5 `shiftL` 40) .|. (b 6 `shiftL` 48) .|. (b 7 `shiftL` 56)
