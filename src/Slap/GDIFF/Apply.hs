module Slap.GDIFF.Apply
  ( applyGDIFF
  ) where

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..), commandOutputSize)
import Slap.Binary (copyByteStringRange)
import Slap.Measure (Offset(..), FileSize(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)

applyGDIFF :: GDiffPatch -> ByteString -> ByteString
applyGDIFF patch source
  | totalSize == 0 = ByteString.empty
  | otherwise = unsafeCreate (fromIntegral totalSize) $ \outputPointer ->
      applyLoop outputPointer 0 (gdiffCommands patch)
  where
    totalSize = sum (map commandOutputSize (gdiffCommands patch))

    applyLoop :: Ptr Word8 -> Int -> [GDiffCommand] -> IO ()
    applyLoop _outputPointer _position [] = pure ()
    applyLoop outputPointer position (command:remaining) = case command of
      GDiffData payload -> do
        let dataLength = ByteString.length payload
        copyByteStringRange outputPointer position payload 0 dataLength
        applyLoop outputPointer (position + dataLength) remaining
      GDiffCopy sourceOffset copyLength -> do
        let sourceStart = fromIntegral (unOffset sourceOffset)
            count = fromIntegral (unFileSize copyLength) :: Int
        copyByteStringRange outputPointer position source sourceStart count
        applyLoop outputPointer (position + count) remaining
