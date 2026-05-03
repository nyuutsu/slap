{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Apply
  ( applyAPSGBA
  , safeSlice
  ) where

import Slap.APSGBA.Types
import Slap.Binary (copyByteStringRange)
import Slap.Error (SlapError)
import Slap.Measure (FileSize(..), Offset(..))

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits (xor)
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

applyAPSGBA :: APSGBAPatch -> SourceFileContents -> Either SlapError TargetFileContents
applyAPSGBA (APSGBAPatch header records) (SourceFileContents source) = Right $ TargetFileContents $ unsafeCreate targetSize $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength targetSize)
    when (targetSize > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (targetSize - sourceLength)
    forM_ records $ \(APSGBARecord recordOffset _ _ xorPayload) -> do
      let blockOffset = unOffset recordOffset
          writeBase = targetPointer `plusPtr` blockOffset
          loop !byteOffset
            | byteOffset >= apsGbaBlockSize = pure ()
            | otherwise = do
                let position = blockOffset + byteOffset
                when (position < targetSize) $ do
                  original <- peekByteOff writeBase byteOffset :: IO Word8
                  pokeByteOff writeBase byteOffset
                    (original `xor` ByteString.index xorPayload byteOffset)
                loop (byteOffset + 1)
      loop 0
  where
    sourceLength = ByteString.length source
    targetSize = unFileSize (apsGbaTargetSize header)

safeSlice :: Int -> Int -> ByteString -> ByteString
safeSlice offset sliceLength input
  | offset >= ByteString.length input = ByteString.empty
  | otherwise = ByteString.take sliceLength (ByteString.drop offset input)
