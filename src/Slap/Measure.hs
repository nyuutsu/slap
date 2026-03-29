{-# LANGUAGE StrictData #-}

module Slap.Measure
  ( -- * Newtypes
    Offset(..)
  , Length(..)
  , FileSize(..)
  , Delta(..)
  , Position(..)
    -- * Records
  , Hunk(..)
  , UndoHunk(..)
  , EncodedHunk(..)
  , EncodingLimits(..)
    -- * Conversions
  , offsetToInt
  , fileSizeToInt
  , lengthToFileSize
  , lengthToOffset
    -- * Seeking
  , seekTo
    -- * Arithmetic
  , advance
  , distance
  , fitsWithin
  , byteLength
  , hunkEnd
    -- * Narrowing
  , narrowHunk
  , narrowHunks
  , narrowHunkUnbounded
  , narrowHunksUnbounded
    -- * Memory
  , copyRegion
    -- * Encoding limits
  , ipsLimits
  , ips32Limits
  , ebpLimits
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Int (Int64)
import Data.Word (Word8)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, plusPtr, castPtr)
import Numeric (showHex)
import System.IO (Handle, SeekMode(AbsoluteSeek), hSeek)

----------------------------------------------------------------------------
-- Newtypes
----------------------------------------------------------------------------

newtype Offset   = Offset   { unOffset   :: Int64 } deriving (Eq, Ord, Show)
newtype Length   = Length   { unLength   :: Int   } deriving (Eq, Ord, Show)
newtype FileSize = FileSize { unFileSize :: Int64 } deriving (Eq, Ord, Show)
newtype Delta    = Delta    { unDelta    :: Int64 } deriving (Eq, Ord, Show)
newtype Position = Position { unPosition :: Int   } deriving (Eq, Ord, Show)

----------------------------------------------------------------------------
-- Records
----------------------------------------------------------------------------

data Hunk = Hunk
  { hunkOffset  :: !Offset
  , hunkPayload :: !ByteString
  } deriving (Show)

data UndoHunk = UndoHunk
  { undoOffset   :: !Offset
  , undoPayload  :: !ByteString
  , undoOriginal :: !ByteString
  } deriving (Show)

data EncodedHunk = EncodedHunk
  { encodedOffset  :: !Int
  , encodedPayload :: !ByteString
  } deriving (Eq, Show)

data EncodingLimits = EncodingLimits
  { maximumOffset  :: !Offset
  , sentinelOffset :: !(Maybe Offset)
  , formatLabel    :: !String
  } deriving (Show)

----------------------------------------------------------------------------
-- Instances
----------------------------------------------------------------------------

instance Semigroup Length where
  Length left <> Length right = Length (left + right)

instance Monoid Length where
  mempty = Length 0

----------------------------------------------------------------------------
-- Conversions
----------------------------------------------------------------------------

offsetToInt :: Offset -> Int
offsetToInt = fromIntegral . unOffset

fileSizeToInt :: FileSize -> Int
fileSizeToInt = fromIntegral . unFileSize

lengthToFileSize :: Length -> FileSize
lengthToFileSize (Length lengthValue) = FileSize (fromIntegral lengthValue)

lengthToOffset :: Length -> Offset
lengthToOffset (Length lengthValue) = Offset (fromIntegral lengthValue)

----------------------------------------------------------------------------
-- Seeking
----------------------------------------------------------------------------

seekTo :: Handle -> Offset -> IO ()
seekTo handle targetOffset =
  hSeek handle AbsoluteSeek (fromIntegral (unOffset targetOffset))

----------------------------------------------------------------------------
-- Arithmetic
----------------------------------------------------------------------------

advance :: Offset -> Length -> Offset
advance (Offset startOffset) (Length strideLength) =
  Offset (startOffset + fromIntegral strideLength)

distance :: Offset -> Offset -> Length
distance (Offset startOffset) (Offset endOffset) =
  Length (fromIntegral (endOffset - startOffset))

fitsWithin :: Offset -> Length -> FileSize -> Bool
fitsWithin (Offset regionStart) (Length regionLength) (FileSize totalSize) =
  regionStart + fromIntegral regionLength <= totalSize

byteLength :: ByteString -> Length
byteLength bytes = Length (ByteString.length bytes)

hunkEnd :: Hunk -> Offset
hunkEnd hunk = advance (hunkOffset hunk) (byteLength (hunkPayload hunk))

----------------------------------------------------------------------------
-- Narrowing
----------------------------------------------------------------------------

narrowHunk :: EncodingLimits -> Hunk -> Either String EncodedHunk
narrowHunk limits hunk
  | unOffset (hunkOffset hunk) > unOffset (maximumOffset limits) =
      Left (formatLabel limits ++ ": hunk offset 0x"
            ++ showHex (unOffset (hunkOffset hunk)) ""
            ++ " exceeds maximum offset 0x"
            ++ showHex (unOffset (maximumOffset limits)) "")
  | Just sentinel <- sentinelOffset limits
  , hunkOffset hunk == sentinel =
      Left (formatLabel limits ++ ": hunk offset 0x"
            ++ showHex (unOffset sentinel) ""
            ++ " collides with sentinel 0x"
            ++ showHex (unOffset sentinel) "")
  | otherwise =
      Right EncodedHunk
        { encodedOffset  = fromIntegral (unOffset (hunkOffset hunk))
        , encodedPayload = hunkPayload hunk
        }

narrowHunks :: EncodingLimits -> [Hunk] -> Either String [EncodedHunk]
narrowHunks limits = traverse (narrowHunk limits)

narrowHunkUnbounded :: Hunk -> EncodedHunk
narrowHunkUnbounded hunk = EncodedHunk
  { encodedOffset  = fromIntegral (unOffset (hunkOffset hunk))
  , encodedPayload = hunkPayload hunk
  }

narrowHunksUnbounded :: [Hunk] -> [EncodedHunk]
narrowHunksUnbounded = map narrowHunkUnbounded

----------------------------------------------------------------------------
-- Memory
----------------------------------------------------------------------------

copyRegion :: Ptr Word8 -> Offset -> ByteString -> Int -> Length -> IO ()
copyRegion _           _                 _      _              regionLength | unLength regionLength <= 0 = pure ()
copyRegion destination destinationOffset source sourcePosition regionLength =
  UnsafeByteString.unsafeUseAsCStringLen source $ \(sourcePointer, _) ->
    copyBytes (destination `plusPtr` fromIntegral (unOffset destinationOffset))
              (castPtr sourcePointer `plusPtr` sourcePosition)
              (unLength regionLength)

----------------------------------------------------------------------------
-- Encoding limits
----------------------------------------------------------------------------

ipsLimits :: EncodingLimits
ipsLimits = EncodingLimits
  { maximumOffset  = Offset 0xFFFFFF
  , sentinelOffset = Just (Offset 0x454F46)
  , formatLabel    = "IPS"
  }

ips32Limits :: EncodingLimits
ips32Limits = EncodingLimits
  { maximumOffset  = Offset 0xFFFFFFFF
  , sentinelOffset = Just (Offset 0x45454F46)
  , formatLabel    = "IPS32"
  }

ebpLimits :: EncodingLimits
ebpLimits = EncodingLimits
  { maximumOffset  = Offset 0xFFFFFF
  , sentinelOffset = Just (Offset 0x454F46)
  , formatLabel    = "EBP"
  }
