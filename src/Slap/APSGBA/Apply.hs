{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Apply
  ( applyAPSGBA
  , applyGBARecords
  , applyAPSGBAMemory
  , safeSlice
  ) where

import Slap.APSGBA.Types
import Slap.Binary (copyByteStringRange)
import Slap.Measure (FileSize(..), Offset(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits (xor)
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

applyAPSGBA :: APSGBAPatch -> FilePath -> IO Int
applyAPSGBA (APSGBAPatch header records) target = do
  source <- ByteString.readFile target
  let targetSize = unFileSize (apsGbaTargetSize header)
      padded = if ByteString.length source < targetSize
               then source <> ByteString.replicate (targetSize - ByteString.length source) 0
               else source
  result <- applyGBARecords padded records
  ByteString.writeFile target (ByteString.take targetSize result)
  pure (length records)

applyGBARecords :: ByteString -> [APSGBARecord] -> IO ByteString
applyGBARecords source [] = pure source
applyGBARecords source (APSGBARecord recordOffset _ _ xorPayload : rest) = do
  let blockOffset = unOffset recordOffset
      blockSize = apsGbaBlockSize
      before = ByteString.take blockOffset source
      sourceBlock = ByteString.take blockSize (ByteString.drop blockOffset source)
      paddedBlock = if ByteString.length sourceBlock < blockSize
                    then sourceBlock <> ByteString.replicate (blockSize - ByteString.length sourceBlock) 0
                    else sourceBlock
      patchedBlock = ByteString.packZipWith xor paddedBlock xorPayload
      after = ByteString.drop (blockOffset + blockSize) source
      result = before <> patchedBlock <> after
  applyGBARecords result rest

applyAPSGBAMemory :: APSGBAPatch -> ByteString -> ByteString
applyAPSGBAMemory (APSGBAPatch header records) source = unsafeCreate targetSize $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength targetSize)
    when (targetSize > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (targetSize - sourceLength)
    forM_ records $ \(APSGBARecord recordOffset _ _ xorPayload) -> do
      let blockOffset = unOffset recordOffset
      forM_ [0..apsGbaBlockSize - 1] $ \index -> do
        let position = blockOffset + index
        when (position < targetSize) $ do
          original <- peekByteOff targetPointer position :: IO Word8
          pokeByteOff targetPointer position (original `xor` ByteString.index xorPayload index)
  where
    sourceLength = ByteString.length source
    targetSize = unFileSize (apsGbaTargetSize header)

safeSlice :: Int -> Int -> ByteString -> ByteString
safeSlice offset sliceLength input
  | offset >= ByteString.length input = ByteString.empty
  | otherwise = ByteString.take sliceLength (ByteString.drop offset input)
