module Slap.Binary
  ( -- * Little-endian readers
    getWord16LE
  , getWord32LE
  , getInt64LE
    -- * Big-endian readers
  , getWord16BE
  , getWord24BE
  , getWord32BE
  , getInt64BE
    -- * Variable-length integers
  , VarintResult(..)
  , getByuuVarint
  , getVcdiffVarint
    -- * Builders
  , putWord16BE
  , putWord32LE
  , putByuuVarint
    -- * CRC-16 / Adler-32
  , crc16
  , adler32  -- re-exported from Slap.FFI
    -- * Cryptographic hashes
  , md5
  , sha1
  , sha256
    -- * Bulk memory operations
  , copyByteStringRange
  , copyRegion
  , copyInPlace
  , viewBytesInRange
    -- * Diff
  , diffHunks
    -- * String utilities
  , trimNull
    -- * Additional builders
  , putWord16LE
  , putWord32BE
  , putInt64BE
  ) where

import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.ByteString.Builder (Builder, word8)
import Data.Array (Array, listArray, (!))
import Data.Bits (shiftL, shiftR, xor, (.&.), (.|.), testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)
import Foreign.Marshal.Utils (copyBytes, moveBytes)
import Foreign.Ptr (Ptr, plusPtr, castPtr)
import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as ByteArray
import Slap.Checksum (Adler32, CRC16(..), MD5Hash(..), SHA1Hash(..))
import Slap.FFI (rustyAdler32)
import Slap.Measure (Offset(..), Length(..), Hunk(..))

----------------------------------------------------------------------------
-- Little-endian readers
----------------------------------------------------------------------------

getWord16LE :: Int -> ByteString -> Word16
getWord16LE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word16
  in byteAt 0 .|. (byteAt 1 `shiftL` 8)

getWord32LE :: Int -> ByteString -> Word32
getWord32LE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word32
  in byteAt 0 .|. (byteAt 1 `shiftL` 8) .|. (byteAt 2 `shiftL` 16) .|. (byteAt 3 `shiftL` 24)

getInt64LE :: Int -> ByteString -> Int64
getInt64LE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Int64
  in byteAt 0 .|. (byteAt 1 `shiftL` 8) .|. (byteAt 2 `shiftL` 16) .|. (byteAt 3 `shiftL` 24)
     .|. (byteAt 4 `shiftL` 32) .|. (byteAt 5 `shiftL` 40) .|. (byteAt 6 `shiftL` 48) .|. (byteAt 7 `shiftL` 56)

----------------------------------------------------------------------------
-- Big-endian readers
----------------------------------------------------------------------------

getWord16BE :: Int -> ByteString -> Word16
getWord16BE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word16
  in (byteAt 0 `shiftL` 8) .|. byteAt 1

getWord24BE :: Int -> ByteString -> Word32
getWord24BE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word32
  in (byteAt 0 `shiftL` 16) .|. (byteAt 1 `shiftL` 8) .|. byteAt 2

getWord32BE :: Int -> ByteString -> Word32
getWord32BE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word32
  in (byteAt 0 `shiftL` 24) .|. (byteAt 1 `shiftL` 16) .|. (byteAt 2 `shiftL` 8) .|. byteAt 3

getInt64BE :: Int -> ByteString -> Int64
getInt64BE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Int64
  in (byteAt 0 `shiftL` 56) .|. (byteAt 1 `shiftL` 48) .|. (byteAt 2 `shiftL` 40) .|. (byteAt 3 `shiftL` 32)
     .|. (byteAt 4 `shiftL` 24) .|. (byteAt 5 `shiftL` 16) .|. (byteAt 6 `shiftL` 8) .|. byteAt 7

----------------------------------------------------------------------------
-- Variable-length integers
----------------------------------------------------------------------------

-- | byuu/Near-style varint used by BPS and UPS.
-- LSB-first encoding: each 7-bit group is stored low byte first.
-- High bit clear = more bytes follow. High bit set = final byte.
-- Each continuation adds 1 to accumulator before shifting (the "subtract-one" trick).
-- Returns (value, bytes consumed).
getByuuVarint :: Int -> ByteString -> Either String VarintResult
getByuuVarint offset input = decode offset 0 1 (0 :: Int)
  where
    inputLength = ByteString.length input
    decode position accumulated multiplier !iterations
      | iterations >= 9 =
          Left ("varint overflow at offset " ++ show offset
                ++ " (too many continuation bytes)")
      | position >= inputLength =
          Left ("unterminated varint at offset " ++ show offset
                ++ " (reached end of input after " ++ show (position - offset) ++ " bytes)")
      | otherwise =
          let byte = ByteString.index input position
              payload = fromIntegral (byte .&. 0x7F) :: Int64
              total = accumulated + payload * multiplier
          in if testBit byte 7
             then Right (VarintResult total (position - offset + 1))
             else let nextMultiplier = multiplier `shiftL` 7
                  in decode (position + 1) (total + nextMultiplier) nextMultiplier
                            (iterations + 1)

-- | VCDIFF varint (RFC 3284).  MSB-first: high bit set = more bytes follow.
-- Returns (value, bytes consumed).
getVcdiffVarint :: Int -> ByteString -> Either String VarintResult
getVcdiffVarint offset input = decode offset 0 (0 :: Int)
  where
    inputLength = ByteString.length input
    decode position accumulated !iterations
      | iterations >= 9 =
          Left ("varint overflow at offset " ++ show offset
                ++ " (too many continuation bytes)")
      | position >= inputLength =
          Left ("unterminated varint at offset " ++ show offset
                ++ " (reached end of input after " ++ show (position - offset) ++ " bytes)")
      | otherwise =
          let byte = ByteString.index input position
              total = (accumulated `shiftL` 7) .|. fromIntegral (byte .&. 0x7F)
          in if testBit byte 7
             then decode (position + 1) total (iterations + 1)
             else Right (VarintResult total (position - offset + 1))

----------------------------------------------------------------------------
-- Builders
----------------------------------------------------------------------------

putWord16BE :: Word16 -> Builder
putWord16BE value =
  word8 (fromIntegral (value `shiftR` 8))
  <> word8 (fromIntegral value)

putWord32LE :: Word32 -> Builder
putWord32LE value =
  word8 (fromIntegral (value .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 24) .&. 0xFF))

-- | Encode a non-negative Int64 as a byuu-style varint.
putByuuVarint :: Int64 -> Builder
putByuuVarint = encode
  where
    encode value
      | value <= 0x7F = word8 (fromIntegral value .|. 0x80)
      | otherwise =
          let lowBits = fromIntegral (value .&. 0x7F) :: Word8
              remaining = (value `shiftR` 7) - 1
          in word8 lowBits <> encode remaining

----------------------------------------------------------------------------
-- Cryptographic hashes
----------------------------------------------------------------------------

md5 :: ByteString -> MD5Hash
md5 = MD5Hash . ByteArray.convert . Hash.hashWith Hash.MD5

sha1 :: ByteString -> SHA1Hash
sha1 = SHA1Hash . ByteArray.convert . Hash.hashWith Hash.SHA1

sha256 :: ByteString -> ByteString
sha256 = ByteArray.convert . Hash.hashWith Hash.SHA256

----------------------------------------------------------------------------
-- Bulk memory operations
----------------------------------------------------------------------------

-- | Bulk copy @copyLength@ bytes from a ByteString (at @sourceOffset@) to a
-- raw pointer (at @destinationOffset@).  Uses memcpy internally.
copyByteStringRange :: Ptr Word8 -> Int -> ByteString -> Int -> Int -> IO ()
copyByteStringRange destination destinationOffset source sourceOffset copyLength =
  when (copyLength > 0) $
    UnsafeByteString.unsafeUseAsCStringLen source $ \(sourcePointer, _) ->
      copyBytes (destination `plusPtr` destinationOffset)
                (castPtr sourcePointer `plusPtr` sourceOffset)
                copyLength

-- | Bulk copy @regionLength@ bytes from a ByteString (at a typed
-- 'Offset') to a raw pointer (at a typed 'Offset'). Uses memcpy
-- internally. A no-op when @regionLength@ is zero or negative.
copyRegion :: Ptr Word8 -> Offset -> ByteString -> Offset -> Length -> IO ()
copyRegion destination destinationOffset source sourcePosition regionLength =
  when (unLength regionLength > 0) $
    UnsafeByteString.unsafeUseAsCStringLen source $ \(sourcePointer, _) ->
      copyBytes (destination `plusPtr` unOffset destinationOffset)
                (castPtr sourcePointer `plusPtr` unOffset sourcePosition)
                (unLength regionLength)

-- | The bytes in a given range of a 'ByteString' — the subrange
-- starting at 'Offset' and continuing for 'Length' bytes. The input
-- buffer is unchanged; the result is a view (a shared substring in
-- the 'ByteString' sense, O(1)). Out-of-range arguments are handled
-- gracefully by the underlying 'ByteString.drop' / 'ByteString.take':
-- a starting 'Offset' past the end yields an empty result, and a
-- 'Length' that runs past the end yields the bytes that exist.
viewBytesInRange :: Offset -> Length -> ByteString -> ByteString
viewBytesInRange rangeStart rangeLength input =
  ByteString.take (unLength rangeLength) (ByteString.drop (unOffset rangeStart) input)

-- | Copy @regionLength@ bytes from one position in a buffer to
-- another position in the SAME buffer. Used by apply workers for
-- in-buffer copies (e.g., BPS TargetCopy's non-overlapping back
-- references). Uses C @memmove@ under the hood, so it's correct
-- even when the source and destination regions overlap — but
-- callers are responsible for knowing whether overlap is
-- semantically correct for their use case. A no-op when
-- @regionLength@ is zero or negative.
copyInPlace :: Ptr Word8 -> Offset -> Offset -> Length -> IO ()
copyInPlace buffer sourceOffset destinationOffset regionLength =
  when (unLength regionLength > 0) $
    moveBytes (buffer `plusPtr` unOffset destinationOffset)
              (buffer `plusPtr` unOffset sourceOffset)
              (unLength regionLength)

----------------------------------------------------------------------------
-- CRC-16/IBM (reflected polynomial 0xA001, init 0x0000)
----------------------------------------------------------------------------

crc16 :: ByteString -> CRC16
crc16 = CRC16 . ByteString.foldl' updateChecksum 0
  where
    updateChecksum :: Word16 -> Word8 -> Word16
    updateChecksum checksum byte =
      let tableIndex = fromIntegral ((checksum `xor` fromIntegral byte) .&. 0xFF)
      in (checksum `shiftR` 8) `xor` (crc16Table ! tableIndex)

crc16Table :: Array Word16 Word16
crc16Table = listArray (0, 255) [computeEntry entry | entry <- [0..255]]
  where
    computeEntry :: Word16 -> Word16
    computeEntry initial = iterate reflect initial !! 8
    reflect :: Word16 -> Word16
    reflect checksum
      | testBit checksum 0 = (checksum `shiftR` 1) `xor` 0xA001
      | otherwise           = checksum `shiftR` 1

----------------------------------------------------------------------------
-- Adler-32 (RFC 1950) — via rusty-slap
----------------------------------------------------------------------------

adler32 :: ByteString -> Adler32
adler32 = rustyAdler32

----------------------------------------------------------------------------
-- Diff
----------------------------------------------------------------------------

-- | Maximum gap (in bytes) between adjacent diff hunks that triggers merging.
mergeGapThreshold :: Int
mergeGapThreshold = 5

-- | Find contiguous regions where two ByteStrings differ.
-- Merges nearby hunks (gap <= mergeGapThreshold bytes) to reduce record count.
-- Returns [Hunk] from the second ByteString.
diffHunks :: ByteString -> ByteString -> [Hunk]
diffHunks original modified = mergeNearby (scanDiffs 0 ++ extension)
  where
    originalLength = ByteString.length original
    modifiedLength = ByteString.length modified
    sharedLength = min originalLength modifiedLength
    extension
      | modifiedLength > originalLength = [Hunk (Offset originalLength) (ByteString.drop originalLength modified)]
      | otherwise                       = []
    scanDiffs position
      | position >= sharedLength = []
      | ByteString.index original position == ByteString.index modified position = scanDiffs (position + 1)
      | otherwise =
          let diffEnd = findDiffEnd (position + 1)
          in Hunk (Offset position) (ByteString.take (diffEnd - position) (ByteString.drop position modified)) : scanDiffs diffEnd
    findDiffEnd position
      | position >= sharedLength = sharedLength
      | ByteString.index original position /= ByteString.index modified position = findDiffEnd (position + 1)
      | otherwise = position
    mergeNearby [] = []
    mergeNearby [hunk] = [hunk]
    mergeNearby (Hunk firstOffset firstData : Hunk nextOffset nextData : rest)
      | unOffset nextOffset - unOffset firstOffset - ByteString.length firstData <= mergeGapThreshold =
          let merged = ByteString.take (unOffset nextOffset + ByteString.length nextData - unOffset firstOffset)
                         (ByteString.drop (unOffset firstOffset) modified)
          in mergeNearby (Hunk firstOffset merged : rest)
      | otherwise = Hunk firstOffset firstData : mergeNearby (Hunk nextOffset nextData : rest)


----------------------------------------------------------------------------
-- Additional builders
----------------------------------------------------------------------------

putWord16LE :: Word16 -> Builder
putWord16LE value =
  word8 (fromIntegral (value .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 8) .&. 0xFF))

putWord32BE :: Word32 -> Builder
putWord32BE value =
  word8 (fromIntegral (value `shiftR` 24))
  <> word8 (fromIntegral ((value `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (value .&. 0xFF))

putInt64BE :: Int64 -> Builder
putInt64BE value =
  word8 (fromIntegral (value `shiftR` 56))
  <> word8 (fromIntegral ((value `shiftR` 48) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 40) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 32) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 24) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (value .&. 0xFF))

----------------------------------------------------------------------------
-- Variable-length integer result
----------------------------------------------------------------------------

-- | Result of decoding a variable-length integer: the decoded
-- value followed by the number of bytes consumed from the input.
data VarintResult = VarintResult !Int64 !Int
  deriving (Show)

----------------------------------------------------------------------------
-- String utilities
----------------------------------------------------------------------------

-- | Strip trailing null bytes from a ByteString.
trimNull :: ByteString -> ByteString
trimNull = ByteString.takeWhile (/= 0)

