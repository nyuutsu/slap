{-# LANGUAGE DerivingVia #-}

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

import Data.Aeson (ToJSON)
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Word (Word16, Word32, Word64)
import Numeric (showHex)

import Slap.JSON.Bytes (BytesAsBase64(..))

newtype CRC32 = CRC32 { unCRC32 :: Word32 }
  deriving (Eq, Ord, Show)
  deriving newtype (ToJSON)

newtype CRC16 = CRC16 { unCRC16 :: Word16 }
  deriving (Eq, Ord, Show)

newtype Adler32 = Adler32 { unAdler32 :: Word32 }
  deriving (Eq, Ord, Show)
  deriving newtype (ToJSON)

newtype MD5Hash = MD5Hash { unMD5Hash :: ByteString }
  deriving (Eq, Ord, Show)
  deriving (ToJSON) via BytesAsBase64

newtype SHA1Hash = SHA1Hash { unSHA1Hash :: ByteString }
  deriving (Eq, Ord, Show)
  deriving (ToJSON) via BytesAsBase64

-- | A CRC32 value that a patch declared or stored.
newtype ExpectedCRC32 = ExpectedCRC32 { unExpectedCRC32 :: CRC32 }
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | A CRC32 value that was computed from the actual data.
newtype ActualCRC32 = ActualCRC32 { unActualCRC32 :: CRC32 }
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | A 'Word64' as zero-padded lowercase hex of the given digit width.
showZeroPaddedHex :: Int -> Word64 -> Text
showZeroPaddedHex width value =
  let digits = showHex value ""
  in Text.pack (replicate (width - length digits) '0' ++ digits)

-- | "001a3b4c" — 8-digit zero-padded hex.
showCRC32 :: CRC32 -> Text
showCRC32 (CRC32 value) = showZeroPaddedHex 8 (fromIntegral value)

-- | "1a3b" — 4-digit zero-padded hex.
showCRC16 :: CRC16 -> Text
showCRC16 (CRC16 value) = showZeroPaddedHex 4 (fromIntegral value)

-- | "001a3b4c" — 8-digit zero-padded hex.
showAdler32 :: Adler32 -> Text
showAdler32 (Adler32 value) = showZeroPaddedHex 8 (fromIntegral value)
