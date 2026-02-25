{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.UPS
  ( UPSBlock(..)
  , UPSPatch(..)
  , parseUPS
  , applyUPS
  , createUPS
  , upsMeta
  , upsInfo
  ) where

-- Canonical reference: https://www.romhacking.net/documents/392/ (byuu UPS spec, near.sh mirror)

import Patch.Binary (getWord32LE, putWord32LE, putByuuVarint)
import Patch.FFI (rustyCRC32)
import Patch.Get (Get, runGet, getByte, byuuVarint, atEnd, failGet)
import Control.Monad (when)
import Patch.Format (showCRC, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.Bits (xor)
import Data.Int (Int64)
import Data.Word (Word32)

data UPSBlock = UPSBlock
  { upsSkip    :: Int64       -- bytes to skip (copy from source unchanged)
  , upsXorData :: ByteString  -- nonzero XOR bytes (terminated by 0x00 in file)
  } deriving (Show)

data UPSPatch = UPSPatch
  { upsSourceSize :: Int64
  , upsTargetSize :: Int64
  , upsBlocks     :: [UPSBlock]
  , upsSourceCRC  :: Word32
  , upsTargetCRC  :: Word32
  , upsPatchCRC   :: Word32
  } deriving (Show)

parseUPS :: ByteString -> Either String UPSPatch
parseUPS bs
  | BS.length bs < 4 = Left "UPS: input too short"
  | BS.take 4 bs /= "UPS1" = Left "not a UPS file (bad magic)"
  | BS.length bs < 16 = Left "UPS: truncated footer"
  | otherwise = do
      -- Validate patch CRC
      let storedPatchCRC = getWord32LE (BS.length bs - 4) bs
          actualPatchCRC = rustyCRC32 (BS.take (BS.length bs - 4) bs)
      if storedPatchCRC /= actualPatchCRC
        then Left ("UPS: patch CRC mismatch (stored " ++ showCRC storedPatchCRC
                    ++ ", computed " ++ showCRC actualPatchCRC ++ ")")
        else pure ()
      let srcCRC = getWord32LE (BS.length bs - 12) bs
          tgtCRC = getWord32LE (BS.length bs - 8)  bs
          -- Parse body between magic and footer
          bodyBs = BS.take (BS.length bs - 16) (BS.drop 4 bs)
      (srcSize, tgtSize, blocks) <- runGet parseUPSBody bodyBs
      Right UPSPatch
        { upsSourceSize = srcSize
        , upsTargetSize = tgtSize
        , upsBlocks     = blocks
        , upsSourceCRC  = srcCRC
        , upsTargetCRC  = tgtCRC
        , upsPatchCRC   = storedPatchCRC
        }

parseUPSBody :: Get (Int64, Int64, [UPSBlock])
parseUPSBody = do
  srcSize <- byuuVarint
  tgtSize <- byuuVarint
  when (srcSize < 0) $ failGet "UPS: negative source size"
  when (tgtSize < 0) $ failGet "UPS: negative target size"
  blocks  <- parseBlocks
  pure (srcSize, tgtSize, blocks)

parseBlocks :: Get [UPSBlock]
parseBlocks = do
  done <- atEnd
  if done then pure []
  else do
    skipN <- byuuVarint
    xorBytes <- collectXor []
    rest <- parseBlocks
    pure (UPSBlock skipN xorBytes : rest)
  where
    -- Collect nonzero XOR bytes until 0x00 terminator
    collectXor acc = do
      b <- getByte
      if b == 0x00
        then pure (BS.pack (reverse acc))
        else collectXor (b : acc)

-- Caller is responsible for checksum validation.
applyUPS :: UPSPatch -> ByteString -> ByteString
applyUPS patch source =
  let tgtSize = fromIntegral (upsTargetSize patch)
      -- Pad or truncate source to target size for XOR
      padded = if BS.length source >= tgtSize
               then BS.take tgtSize source
               else source <> BS.replicate (tgtSize - BS.length source) 0
      result = BL.toStrict $ toLazyByteString $ applyBlocks (upsBlocks patch) padded 0
  in BS.take tgtSize result

applyBlocks :: [UPSBlock] -> ByteString -> Int -> Builder
applyBlocks [] source pos =
  -- Copy remaining source bytes unchanged
  byteString (BS.drop pos source)
applyBlocks (UPSBlock skip xorBytes : rest) source pos =
  let skipEnd = pos + fromIntegral skip
      -- Copy 'skip' bytes unchanged from source
      unchanged = byteString (BS.take (fromIntegral skip) (BS.drop pos source))
      -- XOR the patch bytes with source bytes at skipEnd
      xorLen = BS.length xorBytes
      xored = BS.packZipWith xor (BS.take xorLen (BS.drop skipEnd source)) xorBytes
      -- Pad if XOR extends beyond source
      extraXor = if skipEnd + xorLen > BS.length source
                 then byteString (BS.drop (BS.length source - skipEnd) xorBytes)
                 else mempty
      -- The terminator position: in the UPS XOR stream, each non-zero run
      -- is followed by a zero (matching byte). Copy it from source unchanged.
      termPos = skipEnd + xorLen
      termByte = if termPos < BS.length source
                 then byteString (BS.singleton (BS.index source termPos))
                 else mempty
  in unchanged <> byteString xored <> extraXor <> termByte
     <> applyBlocks rest source (termPos + 1)

upsMeta :: UPSPatch -> [(String, String)]
upsMeta p =
  [ ("source size", show (upsSourceSize p))
  , ("target size", show (upsTargetSize p))
  , ("source CRC", showCRC (upsSourceCRC p))
  , ("target CRC", showCRC (upsTargetCRC p))
  , ("patch CRC", showCRC (upsPatchCRC p))
  ]

upsInfo :: UPSPatch -> String
upsInfo p = unlines $
  [ "format:      UPS" ]
  ++ map renderField (upsMeta p)
  ++ [ "blocks:      " ++ show (length (upsBlocks p)) ]

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

createUPS :: ByteString -> ByteString -> ByteString
createUPS orig modified =
  let srcCRC = rustyCRC32 orig
      tgtCRC = rustyCRC32 modified
      maxLen = max (BS.length orig) (BS.length modified)
      padSrc = if BS.length orig < maxLen
               then orig <> BS.replicate (maxLen - BS.length orig) 0
               else orig
      padTgt = if BS.length modified < maxLen
               then modified <> BS.replicate (maxLen - BS.length modified) 0
               else modified
      xorBytes = BS.packZipWith xor padSrc padTgt
      blocks = xorToBlocks xorBytes
      body = byteString "UPS1"
             <> putByuuVarint (fromIntegral (BS.length orig))
             <> putByuuVarint (fromIntegral (BS.length modified))
             <> foldMap encodeUPSBlock blocks
             <> putWord32LE srcCRC
             <> putWord32LE tgtCRC
      bodyBs = BL.toStrict (toLazyByteString body)
      patchCRC = rustyCRC32 bodyBs
  in bodyBs <> BL.toStrict (toLazyByteString (putWord32LE patchCRC))

encodeUPSBlock :: UPSBlock -> Builder
encodeUPSBlock (UPSBlock skip xd) =
  putByuuVarint skip
  <> byteString xd
  <> word8 0x00  -- terminator

-- | Convert XOR byte array into UPS blocks (skip + nonzero runs).
xorToBlocks :: ByteString -> [UPSBlock]
xorToBlocks bs = go 0
  where
    len = BS.length bs

    go i
      | i >= len = []
      | otherwise =
          let skip = countZeros i
              runStart = i + fromIntegral skip
          in if runStart >= len
             then []
             else let (xd, end) = collectNonzero runStart
                  in UPSBlock skip xd : go end

    countZeros :: Int -> Int64
    countZeros i = go' i
      where
        go' j
          | j >= len = fromIntegral (j - i)
          | BS.index bs j == 0 = go' (j + 1)
          | otherwise = fromIntegral (j - i)

    collectNonzero :: Int -> (ByteString, Int)
    collectNonzero start = go' start []
      where
        go' j acc
          | j >= len = (BS.pack (reverse acc), j)
          | BS.index bs j == 0 = (BS.pack (reverse acc), j + 1)  -- +1: consume terminator position
          | otherwise = go' (j + 1) (BS.index bs j : acc)

