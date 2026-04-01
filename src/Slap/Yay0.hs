{-# LANGUAGE OverloadedStrings #-}

-- | Yay0 (Nintendo LZSS) decompression.
--
-- Format (16-byte header):
--   0x00: "Yay0" magic
--   0x04: decompressed size (u32 BE)
--   0x08: link table offset (u32 BE)
--   0x0C: chunk data offset (u32 BE)
-- Three interleaved streams after the header:
--   Command bitstream (starts at 0x10)
--   Link table (u16 BE entries at link offset)
--   Chunk/literal data (at chunk offset)
-- Bit=1: copy literal byte from chunk stream
-- Bit=0: back-reference via link entry (count + distance)

module Slap.Yay0 (isYay0, decompressYay0) where

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits (testBit, shiftL, shiftR, (.&.), (.|.))
import Control.Monad (forM_)
import Data.IORef
import Data.Word (Word8)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (poke, peekByteOff, pokeByteOff)

isYay0 :: ByteString.ByteString -> Bool
isYay0 input = ByteString.length input >= 16 && ByteString.take 4 input == "Yay0"

decompressYay0 :: ByteString.ByteString -> Either String ByteString.ByteString
decompressYay0 input
  | ByteString.length input < 16 = Left "Yay0: truncated header"
  | ByteString.take 4 input /= "Yay0" = Left "Yay0: bad magic"
  | decompressedSize <= 0 = Left ("Yay0: invalid decompressed size: " ++ show decompressedSize)
  | linkOffset > ByteString.length input = Left ("Yay0: link offset beyond file (offset " ++ show linkOffset ++ ", file " ++ show (ByteString.length input) ++ " bytes)")
  | chunkOffset > ByteString.length input = Left ("Yay0: chunk offset beyond file (offset " ++ show chunkOffset ++ ", file " ++ show (ByteString.length input) ++ " bytes)")
  | otherwise = Right $ unsafeCreate decompressedSize $ \outputPointer -> do
      commandPositionReference <- newIORef (0x10 :: Int)
      commandBitReference <- newIORef (7 :: Int)
      linkPositionReference   <- newIORef linkOffset
      chunkPositionReference  <- newIORef chunkOffset
      outputPositionReference    <- newIORef (0 :: Int)

      let nextBit = do
            bytePosition <- readIORef commandPositionReference
            bit     <- readIORef commandBitReference
            let bitValue = testBit (ByteString.index input bytePosition) bit
            if bit == 0
              then writeIORef commandPositionReference (bytePosition + 1) >> writeIORef commandBitReference 7
              else writeIORef commandBitReference (bit - 1)
            pure bitValue

          nextChunk :: IO Word8
          nextChunk = do
            position <- readIORef chunkPositionReference
            modifyIORef' chunkPositionReference (+ 1)
            pure (ByteString.index input position)

          nextLink :: IO Int
          nextLink = do
            position <- readIORef linkPositionReference
            modifyIORef' linkPositionReference (+ 2)
            let highByte = fromIntegral (ByteString.index input position) :: Int
                lowByte  = fromIntegral (ByteString.index input (position + 1)) :: Int
            pure ((highByte `shiftL` 8) .|. lowByte)

          decompressLoop :: IO ()
          decompressLoop = do
            written <- readIORef outputPositionReference
            if written >= decompressedSize then pure () else do
              isLiteral <- nextBit
              if isLiteral
                then do
                  literal <- nextChunk
                  poke (outputPointer `plusPtr` written) literal
                  writeIORef outputPositionReference (written + 1)
                  decompressLoop
                else do
                  link <- nextLink
                  let countField = (link `shiftR` 12) .&. 0xF
                      distance = (link .&. 0xFFF) + 1
                  count <- if countField == 0
                    then do
                      extra <- nextChunk
                      pure (fromIntegral extra + 0x12 :: Int)
                    else pure (countField + 2)
                  copyBack outputPointer written distance count
                  writeIORef outputPositionReference (written + count)
                  decompressLoop

      decompressLoop
  where
    readBigEndian32 offset = fromIntegral (ByteString.index input offset) `shiftL` 24
          .|. fromIntegral (ByteString.index input (offset+1)) `shiftL` 16
          .|. fromIntegral (ByteString.index input (offset+2)) `shiftL` 8
          .|. fromIntegral (ByteString.index input (offset+3)) :: Int
    decompressedSize  = readBigEndian32 4
    linkOffset  = readBigEndian32 8
    chunkOffset = readBigEndian32 12

-- Must be byte-by-byte because source and destination can overlap.
copyBack :: Ptr Word8 -> Int -> Int -> Int -> IO ()
copyBack outputPointer written distance count =
  forM_ [0..count-1] $ \index -> do
    value <- peekByteOff outputPointer (written - distance + index) :: IO Word8
    pokeByteOff outputPointer (written + index) value
