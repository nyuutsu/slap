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
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
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
parseUPS input
  | ByteString.length input < 4 = Left "UPS: input too short"
  | ByteString.take 4 input /= "UPS1" = Left "not a UPS file (bad magic)"
  | ByteString.length input < 16 = Left "UPS: truncated footer"
  | otherwise = do
      -- Validate patch CRC
      let storedPatchCRC = getWord32LE (ByteString.length input - 4) input
          actualPatchCRC = rustyCRC32 (ByteString.take (ByteString.length input - 4) input)
      if storedPatchCRC /= actualPatchCRC
        then Left ("UPS: patch CRC mismatch (stored " ++ showCRC storedPatchCRC
                    ++ ", computed " ++ showCRC actualPatchCRC ++ ")")
        else pure ()
      let sourceCRC = getWord32LE (ByteString.length input - 12) input
          targetCRC = getWord32LE (ByteString.length input - 8)  input
          -- Parse body between magic and footer
          bodyBytes = ByteString.take (ByteString.length input - 16) (ByteString.drop 4 input)
      (sourceSize, targetSize, blocks) <- runGet parseUPSBody bodyBytes
      Right UPSPatch
        { upsSourceSize = sourceSize
        , upsTargetSize = targetSize
        , upsBlocks     = blocks
        , upsSourceCRC  = sourceCRC
        , upsTargetCRC  = targetCRC
        , upsPatchCRC   = storedPatchCRC
        }

parseUPSBody :: Get (Int64, Int64, [UPSBlock])
parseUPSBody = do
  sourceSize <- byuuVarint
  targetSize <- byuuVarint
  when (sourceSize < 0) $ failGet "UPS: negative source size"
  when (targetSize < 0) $ failGet "UPS: negative target size"
  blocks  <- parseBlocks
  pure (sourceSize, targetSize, blocks)

parseBlocks :: Get [UPSBlock]
parseBlocks = do
  done <- atEnd
  if done then pure []
  else do
    skipCount <- byuuVarint
    xorBytes <- collectXor []
    remaining <- parseBlocks
    pure (UPSBlock skipCount xorBytes : remaining)
  where
    -- Collect nonzero XOR bytes until 0x00 terminator
    collectXor accumulated = do
      byte <- getByte
      if byte == 0x00
        then pure (ByteString.pack (reverse accumulated))
        else collectXor (byte : accumulated)

-- Caller is responsible for checksum validation.
applyUPS :: UPSPatch -> ByteString -> ByteString
applyUPS patch source =
  let targetSize = fromIntegral (upsTargetSize patch)
      -- Pad or truncate source to target size for XOR
      padded = if ByteString.length source >= targetSize
               then ByteString.take targetSize source
               else source <> ByteString.replicate (targetSize - ByteString.length source) 0
      result = LazyByteString.toStrict $ toLazyByteString $ applyBlocks (upsBlocks patch) padded 0
  in ByteString.take targetSize result

applyBlocks :: [UPSBlock] -> ByteString -> Int -> Builder
applyBlocks [] source position =
  -- Copy remaining source bytes unchanged
  byteString (ByteString.drop position source)
applyBlocks (UPSBlock skip xorBytes : remaining) source position =
  let skipEnd = position + fromIntegral skip
      -- Copy 'skip' bytes unchanged from source
      unchanged = byteString (ByteString.take (fromIntegral skip) (ByteString.drop position source))
      -- XOR the patch bytes with source bytes at skipEnd
      xorLength = ByteString.length xorBytes
      xored = ByteString.packZipWith xor (ByteString.take xorLength (ByteString.drop skipEnd source)) xorBytes
      -- Pad if XOR extends beyond source
      extraXor = if skipEnd + xorLength > ByteString.length source
                 then byteString (ByteString.drop (ByteString.length source - skipEnd) xorBytes)
                 else mempty
      -- The terminator position: in the UPS XOR stream, each non-zero run
      -- is followed by a zero (matching byte). Copy it from source unchanged.
      terminatorPosition = skipEnd + xorLength
      terminatorByte = if terminatorPosition < ByteString.length source
                 then byteString (ByteString.singleton (ByteString.index source terminatorPosition))
                 else mempty
  in unchanged <> byteString xored <> extraXor <> terminatorByte
     <> applyBlocks remaining source (terminatorPosition + 1)

upsMeta :: UPSPatch -> [(String, String)]
upsMeta patch =
  [ ("source size", show (upsSourceSize patch))
  , ("target size", show (upsTargetSize patch))
  , ("source CRC", showCRC (upsSourceCRC patch))
  , ("target CRC", showCRC (upsTargetCRC patch))
  , ("patch CRC", showCRC (upsPatchCRC patch))
  ]

upsInfo :: UPSPatch -> String
upsInfo patch = unlines $
  [ "format:      UPS" ]
  ++ map renderField (upsMeta patch)
  ++ [ "blocks:      " ++ show (length (upsBlocks patch)) ]

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

createUPS :: ByteString -> ByteString -> ByteString
createUPS original modified =
  let sourceCRC = rustyCRC32 original
      targetCRC = rustyCRC32 modified
      maxLength = max (ByteString.length original) (ByteString.length modified)
      paddedSource = if ByteString.length original < maxLength
               then original <> ByteString.replicate (maxLength - ByteString.length original) 0
               else original
      paddedTarget = if ByteString.length modified < maxLength
               then modified <> ByteString.replicate (maxLength - ByteString.length modified) 0
               else modified
      xorBytes = ByteString.packZipWith xor paddedSource paddedTarget
      blocks = xorToBlocks xorBytes
      body = byteString "UPS1"
             <> putByuuVarint (fromIntegral (ByteString.length original))
             <> putByuuVarint (fromIntegral (ByteString.length modified))
             <> foldMap encodeUPSBlock blocks
             <> putWord32LE sourceCRC
             <> putWord32LE targetCRC
      bodyBytes = LazyByteString.toStrict (toLazyByteString body)
      patchCRC = rustyCRC32 bodyBytes
  in bodyBytes <> LazyByteString.toStrict (toLazyByteString (putWord32LE patchCRC))

encodeUPSBlock :: UPSBlock -> Builder
encodeUPSBlock (UPSBlock skip xorData) =
  putByuuVarint skip
  <> byteString xorData
  <> word8 0x00  -- terminator

-- | Convert XOR byte array into UPS blocks (skip + nonzero runs).
xorToBlocks :: ByteString -> [UPSBlock]
xorToBlocks input = scanLoop 0
  where
    inputLength = ByteString.length input

    scanLoop position
      | position >= inputLength = []
      | otherwise =
          let skip = countZeros position
              runStart = position + fromIntegral skip
          in if runStart >= inputLength
             then []
             else let (xorData, end) = collectNonzero runStart
                  in UPSBlock skip xorData : scanLoop end

    countZeros :: Int -> Int64
    countZeros startPosition = countFrom startPosition
      where
        countFrom scanPosition
          | scanPosition >= inputLength = fromIntegral (scanPosition - startPosition)
          | ByteString.index input scanPosition == 0 = countFrom (scanPosition + 1)
          | otherwise = fromIntegral (scanPosition - startPosition)

    collectNonzero :: Int -> (ByteString, Int)
    collectNonzero start = collectFrom start []
      where
        collectFrom scanPosition accumulated
          | scanPosition >= inputLength = (ByteString.pack (reverse accumulated), scanPosition)
          | ByteString.index input scanPosition == 0 = (ByteString.pack (reverse accumulated), scanPosition + 1)  -- +1: consume terminator position
          | otherwise = collectFrom (scanPosition + 1) (ByteString.index input scanPosition : accumulated)
