{-# LANGUAGE OverloadedStrings #-}

module Patch.PPF.Create (createPatch, createPatchPure, encodePPF3) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)
import Data.Maybe (fromMaybe, isJust)

createPatch :: FilePath -> FilePath -> String -> Bool -> Bool -> IO ByteString
createPatch origPath modPath desc includeUndo includeValidation = do
  origBs <- BS.readFile origPath
  modBs  <- BS.readFile modPath
  pure (createPatchPure origBs modBs desc includeUndo includeValidation)

-- | Pure version of PPF3 patch creation from two byte strings.
createPatchPure :: ByteString -> ByteString -> String -> Bool -> Bool -> ByteString
createPatchPure origBs modBs desc includeUndo includeValidation =
  let valBlock    = if includeValidation && BS.length origBs > 0x9320 + 1024
                    then Just (BS.take 1024 (BS.drop 0x9320 origBs))
                    else Nothing
      records     = diffFiles origBs modBs
      undoTriples = if includeUndo then Just records else Nothing
      overlayRecs = map (\(off, new, _) -> (off, new)) records
  in encodePPF3 overlayRecs desc undoTriples valBlock

padDescription :: String -> ByteString
padDescription s =
  let bs = BC.pack (take 50 s)
  in bs <> BS.replicate (50 - BS.length bs) 0x20

buildHeader :: ByteString -> Bool -> Bool -> ByteString -> Builder
buildHeader desc blockCheck hasUndo valBlock =
  byteString "PPF30"                                    -- magic + version
  <> word8 0x02                                          -- encoding method
  <> byteString desc                                     -- 50-byte description
  <> word8 0x00                                          -- image type: BIN
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

-- | Compare two byte strings and produce a list of (offset, newData, oldData) hunks.
-- Each hunk is at most 255 bytes (PPF record limit).
diffFiles :: ByteString -> ByteString -> [(Int64, ByteString, ByteString)]
diffFiles orig modified = go 0
  where
    len = min (BS.length orig) (BS.length modified)

    go i
      | i >= len  = extraBytes
      | BS.index orig i /= BS.index modified i = collectHunk i
      | otherwise = go (i + 1)

    collectHunk start =
      let end   = findEnd start
          count = min 255 (end - start)
      in ( fromIntegral start
         , BS.take count (BS.drop start modified)
         , BS.take count (BS.drop start orig)
         ) : go (start + count)

    findEnd i
      | i >= len = len
      | BS.index orig i /= BS.index modified i = findEnd (i + 1)
      | otherwise = i

    extraBytes
      | BS.length modified > BS.length orig =
          chunkBytes (fromIntegral (BS.length orig))
                     (BS.drop (BS.length orig) modified)
      | otherwise = []

    chunkBytes _ e | BS.null e = []
    chunkBytes off e =
      let count = min 255 (BS.length e)
          nulls = BS.replicate count 0
      in (off, BS.take count e, nulls) : chunkBytes (off + fromIntegral count) (BS.drop count e)

----------------------------------------------------------------------------
-- Encode from pre-built records (used by overlay conversion in Main.hs)
----------------------------------------------------------------------------

-- | Encode a PPF3 patch from pre-split overlay records.
-- Records: [(offset, data)], each data ≤ 255 bytes.
-- Undo triples (if provided): [(offset, new, old)], each ≤ 255 bytes.
encodePPF3 :: [(Int64, ByteString)]
           -> String
           -> Maybe [(Int64, ByteString, ByteString)]
           -> Maybe ByteString
           -> ByteString
encodePPF3 recs desc undoTriples valBlock =
  let descBytes   = padDescription desc
      hasValidate = isJust valBlock
      hasUndo     = isJust undoTriples
      hdr         = buildHeader descBytes hasValidate hasUndo
                      (fromMaybe BS.empty valBlock)
      body = case undoTriples of
        Just trips -> foldMap (encodeRecord True) trips
        Nothing    -> foldMap encodeOverlayRecord recs
  in BL.toStrict (toLazyByteString (hdr <> body))

-- | Encode an overlay record (no undo data).
encodeOverlayRecord :: (Int64, ByteString) -> Builder
encodeOverlayRecord (off, dat) =
  int64LE off
  <> word8 (fromIntegral (BS.length dat))
  <> byteString dat
