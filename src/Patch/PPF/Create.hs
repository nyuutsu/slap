{-# LANGUAGE OverloadedStrings #-}

module Patch.PPF.Create (createPatch, createPatchPure) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)

-- | Create a PPF3 patch by comparing an original file with a modified file.
createPatch :: FilePath -> FilePath -> String -> Bool -> Bool -> IO ByteString
createPatch origPath modPath desc includeUndo includeValidation = do
  origBs <- BS.readFile origPath
  modBs  <- BS.readFile modPath
  pure (createPatchPure origBs modBs desc includeUndo includeValidation)

-- | Pure version of PPF3 patch creation from two byte strings.
createPatchPure :: ByteString -> ByteString -> String -> Bool -> Bool -> ByteString
createPatchPure origBs modBs desc includeUndo includeValidation =
  let descBytes   = padDescription desc
      valBlock    = if includeValidation && BS.length origBs > 0x9320 + 1024
                    then BS.take 1024 (BS.drop 0x9320 origBs)
                    else BS.replicate 1024 0
      records     = diffFiles origBs modBs
      header      = buildHeader descBytes includeValidation includeUndo valBlock
      body        = foldMap (encodeRecord includeUndo) records
  in BL.toStrict (toLazyByteString (header <> body))

-- | Pad or truncate a description to exactly 50 bytes.
padDescription :: String -> ByteString
padDescription s =
  let bs = BC.pack (take 50 s)
  in bs <> BS.replicate (50 - BS.length bs) 0x20

-- | Build the PPF3 header.
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

-- | Encode a single patch record as a Builder.
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
