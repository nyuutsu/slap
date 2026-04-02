{-# LANGUAGE OverloadedStrings #-}

module Slap.RUP.Create
  ( createRUP
  , encodeFixedHeader
  , encodeXorRecord
  , rupTruncationNotes
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
createRUP original modified info romType encoding =
    Right $ LazyByteString.toStrict $ toLazyByteString $
      byteString "NINJA2"                     -- magic (6 bytes)
      <> word8 (fromPatchEncoding encoding)   -- text encoding
      <> byteString (encodeFixedHeader encoding info)  -- rest of 2048-byte header
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
      in XorRecord hunkOffset (ByteString.packZipWith xor oldData newData)

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
-- Fields that exceed their byte width are truncated at the last complete
-- codepoint boundary (UTF-8) or byte boundary (system encoding).
encodeFixedHeader :: PatchEncoding -> RUPInfo -> ByteString
encodeFixedHeader encoding info =
    ByteString.pack $ map byteAt [0 .. headerSize - 8]
  where
    byteAt index = case lookup index fieldBytes of
      Just byte -> byte
      Nothing   -> 0
    fieldBytes = concatMap expandField fields
    expandField (fieldOffset, fieldLength, maybeValue) = case maybeValue of
      Nothing    -> []
      Just value ->
        let truncated = truncateField encoding fieldLength value
        in zip [fieldOffset..fieldOffset+fieldLength-1] (ByteString.unpack (zeroPadTo fieldLength truncated))
    zeroPadTo count input = ByteString.take count input <> ByteString.replicate (max 0 (count - ByteString.length input)) 0
    fields =
      [ (0x007 - 7, 84,   rupAuthor info)
      , (0x05B - 7, 11,   rupVersion info)
      , (0x066 - 7, 256,  rupTitle info)
      , (0x166 - 7, 48,   rupGenre info)
      , (0x196 - 7, 48,   rupLanguage info)
      , (0x1C6 - 7, 8,    rupDate info)
      , (0x1CE - 7, 512,  rupWebsite info)
      , (0x3CE - 7, 1074, rupDescription info)
      ]

-- | Truncate a field value to fit within the given byte width.
-- For UTF-8: walks backward from the limit to find the last complete
-- codepoint boundary.  For system encoding: truncates at the byte boundary.
truncateField :: PatchEncoding -> Int -> ByteString -> ByteString
truncateField _ fieldLength value
  | ByteString.length value <= fieldLength = value
truncateField PatchEncodingSystem fieldLength value = ByteString.take fieldLength value
truncateField PatchEncodingUTF8 fieldLength value = truncateUTF8 fieldLength value

-- | Truncate a UTF-8 ByteString to fit within maxBytes, ensuring the
-- result ends at a complete codepoint boundary.
truncateUTF8 :: Int -> ByteString -> ByteString
truncateUTF8 maxBytes value =
    let candidate = ByteString.take maxBytes value
        candidateLength = ByteString.length candidate
        startIndex = findCodepointStart candidate (candidateLength - 1)
        startByte = ByteString.index candidate startIndex
        expectedLength = utf8CharLength startByte
        availableLength = candidateLength - startIndex
    in if availableLength >= expectedLength
       then candidate
       else ByteString.take startIndex candidate
  where
    -- Walk backward past continuation bytes (0x80–0xBF) to the start byte.
    findCodepointStart bytes index
      | index <= 0                               = 0
      | isUTF8Continuation (ByteString.index bytes index) = findCodepointStart bytes (index - 1)
      | otherwise                                = index
    isUTF8Continuation byte = byte >= 0x80 && byte <= 0xBF
    utf8CharLength byte
      | byte < 0x80 = 1
      | byte < 0xC0 = 1  -- bare continuation byte; treat as single
      | byte < 0xE0 = 2
      | byte < 0xF0 = 3
      | otherwise   = 4

-- | Check which RUPInfo fields would be truncated by encodeFixedHeader,
-- and return a warning note for each one.
rupTruncationNotes :: PatchEncoding -> RUPInfo -> [String]
rupTruncationNotes encoding info = concatMap checkField fields
  where
    checkField (fieldLength, fieldLabel, maybeValue) = case maybeValue of
      Just value | ByteString.length value > fieldLength ->
        ["note: RUP " ++ fieldLabel ++ " truncated to fit " ++ show fieldLength
         ++ "-byte field (was " ++ show (ByteString.length value)
         ++ " bytes as " ++ patchEncodingName encoding ++ ")"]
      _ -> []
    fields =
      [ (84,   "author",      rupAuthor info)
      , (11,   "version",     rupVersion info)
      , (256,  "title",       rupTitle info)
      , (48,   "genre",       rupGenre info)
      , (48,   "language",    rupLanguage info)
      , (8,    "date",        rupDate info)
      , (512,  "website",     rupWebsite info)
      , (1074, "description", rupDescription info)
      ]

encodeXorRecord :: XorRecord -> Builder
encodeXorRecord record =
    word8 0x02                                    -- XOR command
    <> encodeVariableLengthValue (fromIntegral (unOffset (xorRecordOffset record)))   -- offset
    <> encodeVariableLengthValue (fromIntegral (ByteString.length (xorRecordPayload record)))  -- length
    <> byteString (xorRecordPayload record)       -- XOR data
