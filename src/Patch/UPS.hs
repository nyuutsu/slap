{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.UPS
  ( UPSBlock(..)
  , UPSPatch(..)
  , parseUPS
  , applyUPS
  , createUPS
  , upsInfo
  ) where

import Patch.Binary (getByuuVarint, getWord32LE, putWord32LE, putByuuVarint, crc32)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.Bits (xor)
import Data.Int (Int64)
import Data.Word (Word32)
import Numeric (showHex)

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

-- | Parse a UPS patch from raw bytes.
parseUPS :: ByteString -> Either String UPSPatch
parseUPS bs
  | BS.length bs < 4 = Left "too short for UPS header"
  | BS.take 4 bs /= "UPS1" = Left "not a UPS file (bad magic)"
  | BS.length bs < 16 = Left "truncated UPS footer"
  | otherwise = do
      -- Validate patch CRC
      let storedPatchCRC = getWord32LE (BS.length bs - 4) bs
          actualPatchCRC = crc32 (BS.take (BS.length bs - 4) bs)
      if storedPatchCRC /= actualPatchCRC
        then Left ("patch CRC mismatch (stored " ++ showCRC storedPatchCRC
                    ++ ", computed " ++ showCRC actualPatchCRC ++ ")")
        else pure ()
      let (srcSize, n1) = getByuuVarint 4 bs
          (tgtSize, n2) = getByuuVarint (4 + n1) bs
          blocksStart   = 4 + n1 + n2
          blocksEnd     = BS.length bs - 12  -- 3 * CRC32
          blocksBs      = BS.take (blocksEnd - blocksStart) (BS.drop blocksStart bs)
          blocks        = parseBlocks blocksBs
          srcCRC        = getWord32LE (BS.length bs - 12) bs
          tgtCRC        = getWord32LE (BS.length bs - 8)  bs
      Right UPSPatch
        { upsSourceSize = srcSize
        , upsTargetSize = tgtSize
        , upsBlocks     = blocks
        , upsSourceCRC  = srcCRC
        , upsTargetCRC  = tgtCRC
        , upsPatchCRC   = storedPatchCRC
        }

parseBlocks :: ByteString -> [UPSBlock]
parseBlocks bs = go 0
  where
    go pos
      | pos >= BS.length bs = []
      | otherwise =
          let (skip, n) = getByuuVarint pos bs
              (xorBytes, consumed) = collectXor (pos + n)
          in UPSBlock skip xorBytes : go (pos + n + consumed)

    -- Collect nonzero XOR bytes until 0x00 terminator (which is consumed but not included).
    collectXor pos = go' pos []
      where
        go' i acc
          | i >= BS.length bs = (BS.pack (reverse acc), i - pos)
          | BS.index bs i == 0x00 = (BS.pack (reverse acc), i - pos + 1)  -- +1 for the terminator
          | otherwise = go' (i + 1) (BS.index bs i : acc)

-- | Apply a UPS patch to source, producing target.
-- The caller is responsible for checksum validation.
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
      xored = BS.pack
        [ BS.index source (skipEnd + i) `xor` BS.index xorBytes i
        | i <- [0..xorLen-1]
        , skipEnd + i < BS.length source
        ]
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

-- | Human-readable summary of a UPS patch.
upsInfo :: UPSPatch -> String
upsInfo p = unlines $ filter (not . null)
  [ "format:      UPS"
  , "source size: " ++ show (upsSourceSize p)
  , "target size: " ++ show (upsTargetSize p)
  , "blocks:      " ++ show (length (upsBlocks p))
  , "source CRC:  " ++ showCRC (upsSourceCRC p)
  , "target CRC:  " ++ showCRC (upsTargetCRC p)
  , "patch CRC:   " ++ showCRC (upsPatchCRC p)
  ]

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a UPS patch by XOR-diffing two byte strings.
createUPS :: ByteString -> ByteString -> ByteString
createUPS orig modified =
  let srcCRC = crc32 orig
      tgtCRC = crc32 modified
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
      patchCRC = crc32 bodyBs
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

showCRC :: Word32 -> String
showCRC w = let s = showHex w "" in replicate (8 - length s) '0' ++ s
