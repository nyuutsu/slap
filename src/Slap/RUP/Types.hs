{-# LANGUAGE StrictData #-}

module Slap.RUP.Types
  ( RUPPatch(..)
  , RUPRecord(..)
  , RUPInfo(..)
  , OverflowMode(..)
  , toOverflowMode
  , fromOverflowMode
  , parsePackedInteger
  , parsePackedByteString
  , encodeVariableLengthValue
  , variableLengthValueBytes
  , headerSize
  ) where

-- Canonical reference: docs/specs/ninja2-filespec20.txt (Derrick Sobodash, 2006)
-- Archived from http://ninja.cinnamonpirate.com/files/filespec20.txt
-- Secondary: RomPatcher.js modules/RomPatcher.format.rup.js
-- Note: NINJA2 ROM type numbering differs from NINJA1 (10 types vs 18);
-- see docs/specs/ninja2-cliusage.txt. slap stores RUP ROM type as raw Word8.

import Slap.Get (Get, getByte, getBytes)
import Slap.Measure (Length(..), Offset(..), FileSize(..))
import Slap.Format (padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, word8)
import Data.Bits ((.&.), shiftR)
import Data.Int (Int64)
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Overflow mode: how size changes between source and target are handled.
-- 'A' (0x41) = append extra bytes, 'M' (0x4D) = truncate.
-- Spec does not mention XOR-with-0xFF encoding of overflow data;
-- that is a RomPatcher.js convention which we follow for compatibility.
data OverflowMode = OverflowAppend | OverflowTruncate
  deriving (Show, Eq)

toOverflowMode :: Word8 -> Either String OverflowMode
toOverflowMode 0x41 = Right OverflowAppend
toOverflowMode 0x4D = Right OverflowTruncate
toOverflowMode byte = Left ("RUP: unknown overflow type: 0x" ++ padHex 2 (fromIntegral byte))

fromOverflowMode :: OverflowMode -> Word8
fromOverflowMode OverflowAppend   = 0x41  -- 'A'
fromOverflowMode OverflowTruncate = 0x4D  -- 'M'

data RUPPatch = RUPPatch
  { rupHeader         :: RUPInfo
  , rupRecords        :: [RUPRecord]
  , rupOverflow       :: Maybe ByteString  -- on-disk overflow data (XOR'd with 0xFF)
  , rupOverflowType   :: Maybe OverflowMode
  , rupSourceMD5      :: Maybe ByteString  -- 16 bytes
  , rupTargetMD5      :: Maybe ByteString  -- 16 bytes
  , rupSourceSize     :: !FileSize
  , rupTargetSize     :: !FileSize
  , rupPatchEncoding  :: Word8             -- PATCH_ENC (text encoding, byte 6)
  , rupRomType        :: Word8             -- ROM type byte from OPEN_NEW_FILE command
  } deriving (Show)

data RUPInfo = RUPInfo
  { rupAuthor      :: Maybe ByteString
  , rupVersion     :: Maybe ByteString
  , rupTitle       :: Maybe ByteString
  , rupGenre       :: Maybe ByteString
  , rupLanguage    :: Maybe ByteString
  , rupDate        :: Maybe ByteString
  , rupWebsite     :: Maybe ByteString
  , rupDescription :: Maybe ByteString
  } deriving (Show)

data RUPRecord = RUPRecord
  { rupRecordOffset :: !Offset
  , rupRecordXor    :: !ByteString
  } deriving (Show)

----------------------------------------------------------------------------
-- VLV: Variable Length Value (1-byte length prefix, then N LE bytes)
----------------------------------------------------------------------------

parsePackedInteger :: Get Int64
parsePackedInteger = do
  count <- fromIntegral <$> getByte
  packedBytes <- getBytes (Length count)
  -- Only interpret first 8 bytes (enough for Int64); extra bytes are
  -- consumed from the stream but don't contribute to the value.
  let clampedCount = min count 8
  pure $ foldl' (\accumulated index ->
    accumulated + fromIntegral (ByteString.index packedBytes index) * (256 ^ index)) 0 [0..clampedCount-1]

parsePackedByteString :: Get ByteString
parsePackedByteString = do
  dataLength <- fromIntegral <$> parsePackedInteger
  getBytes (Length dataLength)

headerSize :: Int
headerSize = 0x800  -- NINJA2 spec: fixed 2048-byte header

-- | VLV: 1-byte length prefix, then N bytes little-endian.
encodeVariableLengthValue :: Int64 -> Builder
encodeVariableLengthValue 0 = word8 1 <> word8 0
encodeVariableLengthValue value =
  let encodedBytes = variableLengthValueBytes value
  in word8 (fromIntegral (length encodedBytes)) <> foldMap word8 encodedBytes

variableLengthValueBytes :: Int64 -> [Word8]
variableLengthValueBytes 0 = []
variableLengthValueBytes value = fromIntegral (value .&. 0xFF) : variableLengthValueBytes (value `shiftR` 8)
