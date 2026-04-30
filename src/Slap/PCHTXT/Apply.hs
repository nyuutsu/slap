module Slap.PCHTXT.Apply
  ( applyPCHTXTMemory
  ) where

import Slap.PCHTXT.Types (PCHTXTPatch(..), PCHTXTBlock(..), PCHTXTEntry(..))
import Slap.Binary (copyByteStringRange)
import Slap.Error (SlapError)
import Slap.Measure (offsetToInt)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Data.Word (Word8)

-- | Apply a PCHTXT patch in memory: copy source, then overwrite at offsets.
applyPCHTXTMemory :: PCHTXTPatch -> SourceFileContents -> Either SlapError TargetFileContents
applyPCHTXTMemory patch (SourceFileContents source) = Right $ TargetFileContents $ unsafeCreate outputSize $ \outputPointer -> do
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputSize)
    when (outputSize > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
    forM_ entries $ \entry ->
      copyByteStringRange outputPointer (offsetToInt (pchtxtOffset entry)) (pchtxtData entry) 0 (ByteString.length (pchtxtData entry))
  where
    entries = concatMap pchtxtBlockEntries
                (filter pchtxtBlockEnabled (pchtxtBlocks patch))
    sourceLength = ByteString.length source
    outputSize = foldl' max sourceLength
      [ offsetToInt (pchtxtOffset entry) + ByteString.length (pchtxtData entry) | entry <- entries ]
