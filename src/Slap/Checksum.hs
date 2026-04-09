module Slap.Checksum
  ( CRC32(..)
  , CRC16(..)
  , Adler32(..)
  , MD5Hash(..)
  , SHA1Hash(..)
  , ExpectedCRC32(..)
  , ActualCRC32(..)
  , showCRC32
  , showCRC16
  , showAdler32
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word16, Word32, Word64)
import Numeric (showHex)

newtype CRC32 = CRC32 { unCRC32 :: Word32 }
  deriving (Eq, Ord, Show)

newtype CRC16 = CRC16 { unCRC16 :: Word16 }
  deriving (Eq, Ord, Show)

newtype Adler32 = Adler32 { unAdler32 :: Word32 }
  deriving (Eq, Ord, Show)

newtype MD5Hash = MD5Hash { unMD5Hash :: ByteString }
  deriving (Eq, Ord, Show)

newtype SHA1Hash = SHA1Hash { unSHA1Hash :: ByteString }
  deriving (Eq, Ord, Show)

-- | A CRC32 value that a patch declared or stored.
newtype ExpectedCRC32 = ExpectedCRC32 { unExpectedCRC32 :: CRC32 }
  deriving (Eq, Show)

-- | A CRC32 value that was computed from the actual data.
newtype ActualCRC32 = ActualCRC32 { unActualCRC32 :: CRC32 }
  deriving (Eq, Show)

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

-- | "0x001A3B4C" — 8-digit zero-padded hex.
showAdler32 :: Adler32 -> String
showAdler32 (Adler32 value) =
  let digits = showHex (fromIntegral value :: Word64) ""
  in replicate (8 - length digits) '0' ++ digits
