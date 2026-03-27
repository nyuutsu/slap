{-# LANGUAGE OverloadedStrings #-}

module Patch.PPF.Create (encodePPF3, encodeFileIdDiz) where

import Patch.PPF.Types (ImageType(..), fromImageType)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteStringChar
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Int (Int64)
import Data.Maybe (fromMaybe, isJust)

padDescription :: String -> ByteString
padDescription text =
  let encoded = ByteStringChar.pack (take 50 text)
  in encoded <> ByteString.replicate (50 - ByteString.length encoded) 0x20

buildHeader :: ByteString -> Bool -> Bool -> ByteString -> ImageType -> Builder
buildHeader description blockCheck hasUndo validationBlock imageType =
  byteString "PPF30"                                    -- magic + version
  <> word8 0x02                                          -- encoding method
  <> byteString description                              -- 50-byte description
  <> word8 (fromImageType imageType)                       -- image type
  <> word8 (if blockCheck then 0x01 else 0x00)           -- block check flag
  <> word8 (if hasUndo then 0x01 else 0x00)              -- undo flag
  <> word8 0x00                                          -- dummy
  <> if blockCheck then byteString validationBlock else mempty  -- 1024-byte validation block

encodeRecord :: Bool -> (Int64, ByteString, ByteString) -> Builder
encodeRecord hasUndo (offset, patchData, undoData) =
  int64LE offset
  <> word8 (fromIntegral (ByteString.length patchData))
  <> byteString patchData
  <> if hasUndo then byteString undoData else mempty

-- | Encode a PPF3 patch from pre-split records.
-- Records: [(offset, data)], each data ≤ 255 bytes.
-- Undo triples (if provided): [(offset, new, old)], each ≤ 255 bytes.
encodePPF3 :: [(Int64, ByteString)]
           -> String
           -> Maybe [(Int64, ByteString, ByteString)]
           -> Maybe ByteString
           -> ImageType
           -> ByteString
encodePPF3 records description undoTriples validationBlock imageType =
  let descriptionBytes   = padDescription description
      hasValidate = isJust validationBlock
      hasUndo     = isJust undoTriples
      header      = buildHeader descriptionBytes hasValidate hasUndo
                      (fromMaybe ByteString.empty validationBlock) imageType
      body = case undoTriples of
        Just triples -> foldMap (encodeRecord True) triples
        Nothing      -> foldMap encodeWriteRecord records
  in LazyByteString.toStrict (toLazyByteString (header <> body))

-- | Encode a write record (no undo data).
encodeWriteRecord :: (Int64, ByteString) -> Builder
encodeWriteRecord (offset, payload) =
  int64LE offset
  <> word8 (fromIntegral (ByteString.length payload))
  <> byteString payload

-- | Encode a File_ID.diz trailer in PPF3 format (2-byte LE length).
encodeFileIdDiz :: ByteString -> ByteString
encodeFileIdDiz content = LazyByteString.toStrict $ toLazyByteString $
  byteString "@BEGIN_FILE_ID.DIZ"
  <> byteString content
  <> byteString "@END_FILE_ID.DIZ"
  <> word16LE (fromIntegral (ByteString.length content))
