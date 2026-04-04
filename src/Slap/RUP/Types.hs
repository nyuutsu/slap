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
  , toPatchEncoding
  , fromPatchEncoding
  , patchEncodingName
  , encodeRUPString
  , decodeRUPField
  , parsePackedInteger
  , parsePackedByteString
  , encodeVariableLengthValue
  , variableLengthValueBytes
  , headerSize
    -- * Field widths
  , rupAuthorWidth
  , rupVersionWidth
  , rupTitleWidth
  , rupGenreWidth
  , rupLanguageWidth
  , rupDateWidth
  , rupWebsiteWidth
  , rupDescriptionWidth
  ) where

-- Canonical reference: docs/specs/ninja2-filespec20.txt (Derrick Sobodash, 2006)
-- Archived from http://ninja.cinnamonpirate.com/files/filespec20.txt
-- Secondary: RomPatcher.js modules/RomPatcher.format.rup.js
-- Note: NINJA2 ROM type numbering differs from NINJA1 (10 types vs 18);
-- see docs/specs/ninja2-cliusage.txt. slap stores RUP ROM type as raw Word8.

import Slap.Get (Get, getByte, getBytes)
import Slap.Measure (Length(..), Offset(..), FileSize(..))
import Slap.Format (padHex)

import Slap.TextEncoding (encodeUtf8Field, encodeLocaleField,
                          decodeUtf8Field, decodeLocaleField)

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

-- | PATCH_ENC: how text fields in the fixed header are encoded.
-- 0 = system codepage (platform-dependent), 1 = UTF-8 (portable).
-- Unknown values are preserved for round-tripping but treated as system.
data PatchEncoding
  = PatchEncodingUTF8
  | PatchEncodingSystem
  | PatchEncodingUnknown !Word8
  deriving (Show, Eq)

toPatchEncoding :: Word8 -> PatchEncoding
toPatchEncoding 1 = PatchEncodingUTF8
toPatchEncoding 0 = PatchEncodingSystem
toPatchEncoding byte = PatchEncodingUnknown byte

fromPatchEncoding :: PatchEncoding -> Word8
fromPatchEncoding PatchEncodingUTF8          = 1
fromPatchEncoding PatchEncodingSystem        = 0
fromPatchEncoding (PatchEncodingUnknown byte) = byte

patchEncodingName :: PatchEncoding -> String
patchEncodingName PatchEncodingUTF8          = "UTF-8"
patchEncodingName PatchEncodingSystem        = "system"
patchEncodingName (PatchEncodingUnknown byte) = "unknown (" ++ show byte ++ ")"

-- | Encode a String as bytes using the given patch encoding.
encodeRUPString :: PatchEncoding -> String -> ByteString
encodeRUPString PatchEncodingUTF8 = encodeUtf8Field
encodeRUPString _                 = encodeLocaleField

-- | Decode a raw field ByteString to String based on the patch encoding.
-- UTF-8 decodes leniently (invalid bytes become U+FFFD).
-- System and unknown encodings use the system locale.
decodeRUPField :: PatchEncoding -> ByteString -> String
decodeRUPField PatchEncodingUTF8 = decodeUtf8Field
decodeRUPField _                 = decodeLocaleField

data RUPPatch = RUPPatch
  { rupHeader         :: RUPInfo
  , rupRecords        :: [RUPRecord]
  , rupOverflow       :: Maybe ByteString  -- on-disk overflow data (XOR'd with 0xFF)
  , rupOverflowType   :: Maybe OverflowMode
  , rupSourceMD5      :: Maybe ByteString  -- 16 bytes
  , rupTargetMD5      :: Maybe ByteString  -- 16 bytes
  , rupSourceSize     :: !FileSize
  , rupTargetSize     :: !FileSize
  , rupPatchEncoding  :: PatchEncoding      -- PATCH_ENC (text encoding, byte 6)
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

-- | Fixed-header field widths (bytes) per ninja2-filespec20.txt §2.
rupAuthorWidth, rupVersionWidth, rupTitleWidth, rupGenreWidth :: Int
rupLanguageWidth, rupDateWidth, rupWebsiteWidth, rupDescriptionWidth :: Int
rupAuthorWidth      = 84
rupVersionWidth     = 11
rupTitleWidth       = 256
rupGenreWidth       = 48
rupLanguageWidth    = 48
rupDateWidth        = 8
rupWebsiteWidth     = 512
rupDescriptionWidth = 1074

-- | VLV: 1-byte length prefix, then N bytes little-endian.
encodeVariableLengthValue :: Int64 -> Builder
encodeVariableLengthValue 0 = word8 1 <> word8 0
encodeVariableLengthValue value =
  let encodedBytes = variableLengthValueBytes value
  in word8 (fromIntegral (length encodedBytes)) <> foldMap word8 encodedBytes

variableLengthValueBytes :: Int64 -> [Word8]
variableLengthValueBytes 0 = []
variableLengthValueBytes value = fromIntegral (value .&. 0xFF) : variableLengthValueBytes (value `shiftR` 8)
