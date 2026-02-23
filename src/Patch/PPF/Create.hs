{-# LANGUAGE OverloadedStrings #-}

module Patch.PPF.Create (encodePPF3) where

import Patch.PPF.Types (ImageType(..), fromImageType)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)
import Data.Maybe (fromMaybe, isJust)

padDescription :: String -> ByteString
padDescription s =
  let bs = BC.pack (take 50 s)
  in bs <> BS.replicate (50 - BS.length bs) 0x20

buildHeader :: ByteString -> Bool -> Bool -> ByteString -> ImageType -> Builder
buildHeader desc blockCheck hasUndo valBlock imgType =
  byteString "PPF30"                                    -- magic + version
  <> word8 0x02                                          -- encoding method
  <> byteString desc                                     -- 50-byte description
  <> word8 (fromImageType imgType)                       -- image type
  <> word8 (if blockCheck then 0x01 else 0x00)           -- block check flag
  <> word8 (if hasUndo then 0x01 else 0x00)              -- undo flag
  <> word8 0x00                                          -- dummy
  <> if blockCheck then byteString valBlock else mempty  -- 1024-byte validation block

encodeRecord :: Bool -> (Int64, ByteString, ByteString) -> Builder
encodeRecord hasUndo (off, new, old) =
  int64LE off
  <> word8 (fromIntegral (BS.length new))
  <> byteString new
  <> if hasUndo then byteString old else mempty

-- | Encode a PPF3 patch from pre-split records.
-- Records: [(offset, data)], each data ≤ 255 bytes.
-- Undo triples (if provided): [(offset, new, old)], each ≤ 255 bytes.
encodePPF3 :: [(Int64, ByteString)]
           -> String
           -> Maybe [(Int64, ByteString, ByteString)]
           -> Maybe ByteString
           -> ImageType
           -> ByteString
encodePPF3 recs desc undoTriples valBlock imgType =
  let descBytes   = padDescription desc
      hasValidate = isJust valBlock
      hasUndo     = isJust undoTriples
      hdr         = buildHeader descBytes hasValidate hasUndo
                      (fromMaybe BS.empty valBlock) imgType
      body = case undoTriples of
        Just trips -> foldMap (encodeRecord True) trips
        Nothing    -> foldMap encodeWriteRecord recs
  in BL.toStrict (toLazyByteString (hdr <> body))

-- | Encode a write record (no undo data).
encodeWriteRecord :: (Int64, ByteString) -> Builder
encodeWriteRecord (off, dat) =
  int64LE off
  <> word8 (fromIntegral (BS.length dat))
  <> byteString dat
