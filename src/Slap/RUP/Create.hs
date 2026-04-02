{-# LANGUAGE OverloadedStrings #-}

module Slap.RUP.Create
  ( createRUP
  , encodeFixedHeader
  , encodeXorRecord
  ) where

import Slap.RUP.Types
import Slap.Binary (diffHunks, md5)
import Slap.Measure (Offset(..), Hunk(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Bits (xor)
import Data.Word (Word8)

-- | Create a RUP/NINJA2 patch from original and modified ByteStrings.
-- XOR-based records with VLV encoding; handles size changes via overflow.
createRUP :: ByteString -> ByteString -> RUPInfo -> Word8 -> PatchEncoding -> Either String ByteString
createRUP original modified info romType encoding = do
    header <- encodeFixedHeader encoding info
    Right $ LazyByteString.toStrict $ toLazyByteString $
      byteString "NINJA2"                     -- magic (6 bytes)
      <> word8 (fromPatchEncoding encoding)   -- text encoding
      <> byteString header                    -- rest of 2048-byte header
      <> word8 0x01                           -- OPEN_NEW_FILE command
      <> encodeVariableLengthValue 0          -- filename length (empty)
      <> word8 romType                        -- ROM type byte
      <> encodeVariableLengthValue (fromIntegral (ByteString.length original))   -- source size
      <> encodeVariableLengthValue (fromIntegral (ByteString.length modified))   -- target size
      <> byteString (md5 original)            -- source MD5
      <> byteString (md5 modified)            -- target MD5
      <> overflowPart
      <> foldMap encodeXorRecord xorHunks
      <> word8 0x00                           -- END command
  where
    -- XOR hunks over the shared region
    minimumLength = min (ByteString.length original) (ByteString.length modified)
    sourceTrimmed = ByteString.take minimumLength original
    targetTrimmed = ByteString.take minimumLength modified
    -- diffHunks finds changed regions; we then XOR old and new at those positions
    xorHunks = map computeXorHunk (diffHunks sourceTrimmed targetTrimmed)
    computeXorHunk (Hunk hunkOffset newData) =
      let intOffset = fromIntegral (unOffset hunkOffset) :: Int
          oldData = ByteString.take (ByteString.length newData) (ByteString.drop intOffset sourceTrimmed)
      in (intOffset, ByteString.packZipWith xor oldData newData)

    -- Overflow section: emitted whenever sizes differ (parser expects it).
    -- Type byte: 'A' (0x41) = append, 'M' (0x4D) = truncate/minify.
    -- Data is XOR'd with 0xFF on disk (RomPatcher.js convention).
    overflowPart
      | ByteString.length modified > ByteString.length original =
          let extra = ByteString.drop (ByteString.length original) modified
          in word8 (fromOverflowMode OverflowAppend)
             <> encodeVariableLengthValue (fromIntegral (ByteString.length extra))
             <> byteString (ByteString.map (xor 0xFF) extra)
      | ByteString.length modified < ByteString.length original =
          let extra = ByteString.drop (ByteString.length modified) original
          in word8 (fromOverflowMode OverflowTruncate)
             <> encodeVariableLengthValue (fromIntegral (ByteString.length extra))
             <> byteString (ByteString.map (xor 0xFF) extra)
      | otherwise = mempty

-- | Encode a RUPInfo into the fixed header region (bytes 7..2047).
-- Mirrors parseFixedHeader layout: author@0x007/84, version@0x05B/11,
-- title@0x066/256, genre@0x166/48, language@0x196/48, date@0x1C6/8,
-- website@0x1CE/512, description@0x3CE/1074.
-- Rejects any field whose encoded bytes exceed the field width.
encodeFixedHeader :: PatchEncoding -> RUPInfo -> Either String ByteString
encodeFixedHeader encoding info = do
    mapM_ validateField fields
    Right $ ByteString.pack $ map byteAt [0 .. headerSize - 8]
  where
    byteAt index = case lookup index fieldBytes of
      Just byte -> byte
      Nothing   -> 0
    fieldBytes = concatMap expandField fields
    expandField (fieldOffset, fieldLength, _, maybeValue) = case maybeValue of
      Nothing    -> []
      Just value -> zip [fieldOffset..fieldOffset+fieldLength-1] (ByteString.unpack (zeroPadTo fieldLength value))
    zeroPadTo count input = ByteString.take count input <> ByteString.replicate (max 0 (count - ByteString.length input)) 0
    validateField (_, fieldLength, fieldName, Just value)
      | ByteString.length value > fieldLength =
          Left ("RUP " ++ fieldName ++ " exceeds " ++ show fieldLength
                ++ "-byte field limit (got " ++ show (ByteString.length value)
                ++ " bytes as " ++ patchEncodingName encoding ++ ")")
    validateField _ = Right ()
    fields =
      [ (0x007 - 7, 84,   "author",      rupAuthor info)
      , (0x05B - 7, 11,   "version",     rupVersion info)
      , (0x066 - 7, 256,  "title",       rupTitle info)
      , (0x166 - 7, 48,   "genre",       rupGenre info)
      , (0x196 - 7, 48,   "language",    rupLanguage info)
      , (0x1C6 - 7, 8,    "date",        rupDate info)
      , (0x1CE - 7, 512,  "website",     rupWebsite info)
      , (0x3CE - 7, 1074, "description", rupDescription info)
      ]

encodeXorRecord :: (Int, ByteString) -> Builder
encodeXorRecord (recordOffset, payload) =
    word8 0x02                                    -- XOR command
    <> encodeVariableLengthValue (fromIntegral recordOffset)               -- offset
    <> encodeVariableLengthValue (fromIntegral (ByteString.length payload))  -- length
    <> byteString payload                         -- XOR data
