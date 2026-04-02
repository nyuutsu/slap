{-# LANGUAGE StrictData #-}

module Slap.RUP.Types
  ( RUPPatch(..)
  , RUPRecord(..)
  , RUPInfo(..)
  , XorRecord(..)
  , OverflowMode(..)
  , toOverflowMode
  , fromOverflowMode
  , PatchEncoding(..)
  , fromPatchEncoding
  , patchEncodingName
  , encodeRUPString
  , decodeRUPField
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
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified GHC.Foreign as GHC
import System.IO (localeEncoding)
import System.IO.Unsafe (unsafePerformIO)

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

-- | PATCH_ENC: how text fields in the fixed header are encoded.
-- 0 = system codepage (platform-dependent), 1 = UTF-8 (portable).
data PatchEncoding = PatchEncodingUTF8 | PatchEncodingSystem
  deriving (Show, Eq)

fromPatchEncoding :: PatchEncoding -> Word8
fromPatchEncoding PatchEncodingUTF8   = 1
fromPatchEncoding PatchEncodingSystem = 0

patchEncodingName :: PatchEncoding -> String
patchEncodingName PatchEncodingUTF8   = "UTF-8"
patchEncodingName PatchEncodingSystem = "system"

-- | Encode a String as bytes using the given patch encoding.
encodeRUPString :: PatchEncoding -> String -> ByteString
encodeRUPString PatchEncodingUTF8 str = Text.encodeUtf8 (Text.pack str)
encodeRUPString PatchEncodingSystem str = unsafePerformIO $
  GHC.withCStringLen localeEncoding str ByteString.packCStringLen

-- | Decode a raw field ByteString to String based on the PATCH_ENC byte.
-- PATCH_ENC=1 decodes as UTF-8 (lenient: invalid bytes become U+FFFD).
-- PATCH_ENC=0 (or any other value) decodes using the system locale.
decodeRUPField :: Word8 -> ByteString -> String
decodeRUPField 1 bytes = Text.unpack (Text.decodeUtf8Lenient bytes)
decodeRUPField _ bytes = unsafePerformIO $
  ByteString.useAsCStringLen bytes (GHC.peekCStringLen localeEncoding)

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

-- | An XOR record for encoding: offset + XOR'd payload.
data XorRecord = XorRecord
  { xorRecordOffset  :: !Offset
  , xorRecordPayload :: !ByteString
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
