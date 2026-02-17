{-# LANGUAGE OverloadedStrings #-}

module Patch.PPF.Parse (parsePatch) where

import Patch.PPF.Types
import Patch.Binary (getWord16LE, getWord32LE, getInt64LE)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Int (Int64)
import Data.List (unfoldr)

-- | Parse a PPF patch file from raw bytes.
parsePatch :: ByteString -> Either ParseError Patch
parsePatch bs = detectVersion bs >>= \case
  PPF1 -> parsePPF1 bs
  PPF2 -> parsePPF2 bs
  PPF3 -> parsePPF3 bs
  PPF4 -> parsePPF4 bs

-- Version detection: bytes 0-3 as ASCII "PPF1" .. "PPF4".
detectVersion :: ByteString -> Either ParseError Version
detectVersion bs
  | BS.length bs < 6       = Left (TruncatedFile "file too short for header")
  | magic == "PPF1"        = Right PPF1
  | magic == "PPF2"        = Right PPF2
  | magic == "PPF3"        = Right PPF3
  | magic == "PPF4"        = Right PPF4
  | BS.take 3 bs == "PPF"  = Left (UnknownVersion (BS.index bs 3))
  | otherwise              = Left (BadMagic (BS.take 5 bs))
  where magic = BS.take 4 bs

-- PPF1: 56-byte header, then records with 4-byte offsets.
parsePPF1 :: ByteString -> Either ParseError Patch
parsePPF1 bs = do
  requireLen 56 "PPF1 header" bs
  Right Patch
    { patchVersion     = PPF1
    , patchDescription = BS.take 50 (BS.drop 6 bs)
    , patchFileSize    = Nothing
    , patchValidation  = Nothing
    , patchHasUndo     = False
    , patchRecords     = parseRecords32 (BS.drop 56 bs)
    , patchFileId      = Nothing
    }

-- PPF2: 1084-byte header, then records with 4-byte offsets, optional File_ID.diz.
parsePPF2 :: ByteString -> Either ParseError Patch
parsePPF2 bs = do
  requireLen 1084 "PPF2 header" bs
  let fid  = detectFileId getWord32LE 4 bs
      body = stripFileId 4 fid (BS.drop 1084 bs)
  Right Patch
    { patchVersion     = PPF2
    , patchDescription = BS.take 50 (BS.drop 6 bs)
    , patchFileSize    = Just (getWord32LE 56 bs)
    , patchValidation  = Just (Validation BIN (BS.take 1024 (BS.drop 60 bs)))
    , patchHasUndo     = False
    , patchRecords     = parseRecords32 body
    , patchFileId      = fid
    }

-- PPF3: 60 or 1084-byte header, then records with 8-byte offsets, optional undo.
parsePPF3 :: ByteString -> Either ParseError Patch
parsePPF3 bs = do
  requireLen 60 "PPF3 header" bs
  imgType <- case BS.index bs 56 of
    0x00 -> Right BIN
    0x01 -> Right GI
    b    -> Left (UnknownImageType b)
  let hasBlock   = BS.index bs 57 /= 0
      hasUndo    = BS.index bs 58 /= 0
      headerSize = if hasBlock then 1084 else 60
  requireLen headerSize "PPF3 header + validation" bs
  let validation = if hasBlock
        then Just (Validation imgType (BS.take 1024 (BS.drop 60 bs)))
        else Nothing
      fid  = detectFileId getWord16LE 2 bs
      body = stripFileId 2 fid (BS.drop headerSize bs)
  Right Patch
    { patchVersion     = PPF3
    , patchDescription = BS.take 50 (BS.drop 6 bs)
    , patchFileSize    = Nothing
    , patchValidation  = validation
    , patchHasUndo     = hasUndo
    , patchRecords     = parseRecords64 hasUndo body
    , patchFileId      = fid
    }

-- Pyriel's internal format (magic "PPF4"): 60-byte header, records with command byte +
-- 4-byte offsets.  Reverse-engineered from the Suikoden I/II bug fix patchers; not a
-- published spec — only ever generated and consumed within those patchers' Lua runtime.
parsePPF4 :: ByteString -> Either ParseError Patch
parsePPF4 bs = do
  requireLen 60 "PPF4 header" bs
  Right Patch
    { patchVersion     = PPF4
    , patchDescription = BS.take 50 (BS.drop 6 bs)
    , patchFileSize    = Nothing
    , patchValidation  = Nothing
    , patchHasUndo     = False
    , patchRecords     = parseRecords4 (BS.drop 60 bs)
    , patchFileId      = Nothing
    }

-- Parse PPF1/PPF2 records (4-byte offset, 1-byte count, N bytes data).
parseRecords32 :: ByteString -> [Record]
parseRecords32 = unfoldr step
  where
    step bs
      | BS.length bs < 5 = Nothing
      | otherwise =
          let off   = fromIntegral (getWord32LE 0 bs) :: Int64
              count = fromIntegral (BS.index bs 4) :: Int
          in Just ( Record off (BS.take count (BS.drop 5 bs)) Nothing Replace
                  , BS.drop (5 + count) bs )

-- Parse PPF3 records (8-byte offset, 1-byte count, N bytes data, optional undo).
parseRecords64 :: Bool -> ByteString -> [Record]
parseRecords64 hasUndo = unfoldr step
  where
    step bs
      | BS.length bs < 9 = Nothing
      | otherwise =
          let off   = getInt64LE 0 bs
              count = fromIntegral (BS.index bs 8) :: Int
              dat   = BS.take count (BS.drop 9 bs)
              undo  = if hasUndo
                      then Just (BS.take count (BS.drop (9 + count) bs))
                      else Nothing
              skip  = 9 + count + if hasUndo then count else 0
          in Just (Record off dat undo Replace, BS.drop skip bs)

-- Parse PPF4 records (1-byte cmd, 4-byte offset, 1-byte count, N bytes data).
parseRecords4 :: ByteString -> [Record]
parseRecords4 = unfoldr step
  where
    step bs
      | BS.length bs < 6 = Nothing
      | otherwise =
          let cmd   = if BS.index bs 0 == 1 then Append else Replace
              off   = fromIntegral (getWord32LE 1 bs) :: Int64
              count = fromIntegral (BS.index bs 5) :: Int
          in Just ( Record off (BS.take count (BS.drop 6 bs)) Nothing cmd
                  , BS.drop (6 + count) bs )

-- File_ID.diz detection, parameterised by length-field reader and width.
detectFileId :: (Integral a) => (Int -> ByteString -> a) -> Int -> ByteString -> Maybe FileId
detectFileId readLen lenSize bs
  | BS.length bs < 4 + lenSize = Nothing
  | BS.take 4 (BS.drop (BS.length bs - 4 - lenSize) bs) == ".DIZ" =
      let idLen = fromIntegral (readLen (BS.length bs - lenSize) bs)
          trailerSize = 18 + idLen + 16 + lenSize
      in Just (FileId (BS.take idLen (BS.drop (BS.length bs - trailerSize + 18) bs)))
  | otherwise = Nothing

-- Strip File_ID.diz trailer bytes from the record body.
stripFileId :: Int -> Maybe FileId -> ByteString -> ByteString
stripFileId _ Nothing body = body
stripFileId lenSize (Just (FileId content)) body =
  BS.take (BS.length body - 18 - BS.length content - 16 - lenSize) body

requireLen :: Int -> String -> ByteString -> Either ParseError ()
requireLen n ctx bs
  | BS.length bs >= n = Right ()
  | otherwise = Left (TruncatedFile (ctx ++ ": need " ++ show n ++ " bytes, have " ++ show (BS.length bs)))
