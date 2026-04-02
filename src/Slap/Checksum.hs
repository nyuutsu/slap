module Slap.Checksum
  ( CRC32(..)
  , CRC16(..)
  , showCRC32
  , showCRC16
  ) where

import Data.Word (Word16, Word32, Word64)
import Numeric (showHex)

newtype CRC32 = CRC32 { unCRC32 :: Word32 }
  deriving (Eq, Ord, Show)

newtype CRC16 = CRC16 { unCRC16 :: Word16 }
  deriving (Eq, Ord, Show)

-- | "0x001A3B4C" — 8-digit zero-padded hex.
showCRC32 :: CRC32 -> String
showCRC32 (CRC32 value) =
  let digits = showHex (fromIntegral value :: Word64) ""
  in replicate (8 - length digits) '0' ++ digits

-- | "0x1A3B" — 4-digit zero-padded hex.
showCRC16 :: CRC16 -> String
showCRC16 (CRC16 value) =
  let digits = showHex (fromIntegral value :: Word64) ""
  in replicate (4 - length digits) '0' ++ digits
