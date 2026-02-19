{-# LANGUAGE OverloadedStrings #-}

-- | Yay0 (Nintendo LZSS) decompression.
--
-- Star Rod's .mod files use Yay0 to compress PMSR patch data.
-- The uncompressed payload is a standard PMSR patch (offset+data records).
-- This module handles transparent decompression so slap can apply
-- both raw .mod (PMSR magic) and compressed .mod (Yay0 magic) files.
--
-- Format:
--   Header (16 bytes):
--     0x00: "Yay0" magic
--     0x04: decompressed size (u32 BE)
--     0x08: link table offset (u32 BE)
--     0x0C: chunk data offset (u32 BE)
--   Three interleaved streams:
--     Command bitstream (starts at 0x10)
--     Link table (u16 BE entries at link offset)
--     Chunk/literal data (at chunk offset)
--   Bit=1: copy literal byte from chunk stream
--   Bit=0: back-reference via link entry (count + distance)

module Patch.Yay0 (isYay0, decompressYay0) where

import qualified Data.ByteString as BS
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits (testBit, shiftL, shiftR, (.&.), (.|.))
import Data.IORef
import Data.Word (Word8)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (poke, peekByteOff, pokeByteOff)

-- | Check if bytes start with Yay0 magic.
isYay0 :: BS.ByteString -> Bool
isYay0 bs = BS.length bs >= 16 && BS.take 4 bs == "Yay0"

-- | Decompress Yay0-compressed data to raw bytes.
decompressYay0 :: BS.ByteString -> Either String BS.ByteString
decompressYay0 bs
  | BS.length bs < 16 = Left "Yay0: truncated header"
  | BS.take 4 bs /= "Yay0" = Left "Yay0: bad magic"
  | decompSize <= 0 = Left "Yay0: invalid decompressed size"
  | linkOff > BS.length bs = Left "Yay0: link offset beyond file"
  | chunkOff > BS.length bs = Left "Yay0: chunk offset beyond file"
  | otherwise = Right $ unsafeCreate decompSize $ \ptr -> do
      cmdPosRef <- newIORef (0x10 :: Int)
      cmdBitRef <- newIORef (7 :: Int)
      linkRef   <- newIORef linkOff
      chunkRef  <- newIORef chunkOff
      outRef    <- newIORef (0 :: Int)

      let nextBit = do
            bytePos <- readIORef cmdPosRef
            bit     <- readIORef cmdBitRef
            let val = testBit (BS.index bs bytePos) bit
            if bit == 0
              then writeIORef cmdPosRef (bytePos + 1) >> writeIORef cmdBitRef 7
              else writeIORef cmdBitRef (bit - 1)
            pure val

          nextChunk :: IO Word8
          nextChunk = do
            pos <- readIORef chunkRef
            modifyIORef' chunkRef (+ 1)
            pure (BS.index bs pos)

          nextLink :: IO Int
          nextLink = do
            pos <- readIORef linkRef
            modifyIORef' linkRef (+ 2)
            let hi = fromIntegral (BS.index bs pos) :: Int
                lo = fromIntegral (BS.index bs (pos + 1)) :: Int
            pure ((hi `shiftL` 8) .|. lo)

          loop :: IO ()
          loop = do
            out <- readIORef outRef
            if out >= decompSize then pure () else do
              b <- nextBit
              if b
                then do
                  ch <- nextChunk
                  poke (ptr `plusPtr` out) ch
                  writeIORef outRef (out + 1)
                  loop
                else do
                  link <- nextLink
                  let countField = (link `shiftR` 12) .&. 0xF
                      dist = (link .&. 0xFFF) + 1
                  count <- if countField == 0
                    then do
                      extra <- nextChunk
                      pure (fromIntegral extra + 0x12 :: Int)
                    else pure (countField + 2)
                  copyBack ptr out dist count 0
                  writeIORef outRef (out + count)
                  loop

      loop
  where
    r32 off = fromIntegral (BS.index bs off) `shiftL` 24
          .|. fromIntegral (BS.index bs (off+1)) `shiftL` 16
          .|. fromIntegral (BS.index bs (off+2)) `shiftL` 8
          .|. fromIntegral (BS.index bs (off+3)) :: Int
    decompSize = r32 4
    linkOff    = r32 8
    chunkOff   = r32 12

-- | Copy bytes from earlier in the output buffer (back-reference).
-- Must be byte-by-byte because source and destination can overlap.
copyBack :: Ptr Word8 -> Int -> Int -> Int -> Int -> IO ()
copyBack ptr out dist count i
  | i >= count = pure ()
  | otherwise = do
      val <- peekByteOff ptr (out - dist + i) :: IO Word8
      pokeByteOff ptr (out + i) val
      copyBack ptr out dist count (i + 1)
