module Patch.Binary
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
  , getByuuVarint
  , getVcdiffVarint
    -- * Builders
  , putWord16BE
  , putWord32LE
  , putByuuVarint
    -- * CRC-32 / CRC-16
  , crc32
  , crc16
    -- * Bulk memory operations
  , copyBSRange
    -- * Diff
  , diffHunks
  , mergeNearby
    -- * Additional builders
  , putWord16LE
  , putWord32BE
  , putInt64BE
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.ByteString.Builder (Builder, word8)
import Data.Array (Array, listArray, (!))
import Data.Bits (shiftL, shiftR, xor, (.&.), (.|.), testBit, complement)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, plusPtr, castPtr)

----------------------------------------------------------------------------
-- Little-endian readers
----------------------------------------------------------------------------

getWord16LE :: Int -> ByteString -> Word16
getWord16LE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Word16
  in b 0 .|. (b 1 `shiftL` 8)

getWord32LE :: Int -> ByteString -> Word32
getWord32LE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Word32
  in b 0 .|. (b 1 `shiftL` 8) .|. (b 2 `shiftL` 16) .|. (b 3 `shiftL` 24)

getInt64LE :: Int -> ByteString -> Int64
getInt64LE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Int64
  in b 0 .|. (b 1 `shiftL` 8) .|. (b 2 `shiftL` 16) .|. (b 3 `shiftL` 24)
     .|. (b 4 `shiftL` 32) .|. (b 5 `shiftL` 40) .|. (b 6 `shiftL` 48) .|. (b 7 `shiftL` 56)

----------------------------------------------------------------------------
-- Big-endian readers
----------------------------------------------------------------------------

getWord16BE :: Int -> ByteString -> Word16
getWord16BE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Word16
  in (b 0 `shiftL` 8) .|. b 1

getWord24BE :: Int -> ByteString -> Word32
getWord24BE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Word32
  in (b 0 `shiftL` 16) .|. (b 1 `shiftL` 8) .|. b 2

getWord32BE :: Int -> ByteString -> Word32
getWord32BE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Word32
  in (b 0 `shiftL` 24) .|. (b 1 `shiftL` 16) .|. (b 2 `shiftL` 8) .|. b 3

getInt64BE :: Int -> ByteString -> Int64
getInt64BE off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Int64
  in (b 0 `shiftL` 56) .|. (b 1 `shiftL` 48) .|. (b 2 `shiftL` 40) .|. (b 3 `shiftL` 32)
     .|. (b 4 `shiftL` 24) .|. (b 5 `shiftL` 16) .|. (b 6 `shiftL` 8) .|. b 7

----------------------------------------------------------------------------
-- Variable-length integers
----------------------------------------------------------------------------

-- | byuu/Near-style varint used by BPS and UPS.
-- LSB-first encoding: each 7-bit group is stored low byte first.
-- High bit clear = more bytes follow. High bit set = final byte.
-- Each continuation adds 1 to accumulator before shifting (the "subtract-one" trick).
-- Returns (value, bytes consumed).
getByuuVarint :: Int -> ByteString -> (Int64, Int)
getByuuVarint off bs = go off 0 1
  where
    len = BS.length bs
    go i acc shift
      | i >= len  = (acc, i - off)  -- unterminated; return partial to avoid crash
      | otherwise =
          let byte = BS.index bs i
              val  = fromIntegral (byte .&. 0x7F) :: Int64
              acc' = acc + val * shift
          in if testBit byte 7
             then (acc', i - off + 1)
             else let shift' = shift `shiftL` 7
                  in go (i + 1) (acc' + shift') shift'

-- | VCDIFF varint (RFC 3284).  MSB-first: high bit set = more bytes follow.
-- Returns (value, bytes consumed).
getVcdiffVarint :: Int -> ByteString -> (Int64, Int)
getVcdiffVarint off bs = go off 0
  where
    len = BS.length bs
    go i acc
      | i >= len  = (acc, i - off)  -- unterminated; return partial to avoid crash
      | otherwise =
          let byte = BS.index bs i
              acc' = (acc `shiftL` 7) .|. fromIntegral (byte .&. 0x7F)
          in if testBit byte 7
             then go (i + 1) acc'
             else (acc', i - off + 1)

----------------------------------------------------------------------------
-- Builders
----------------------------------------------------------------------------

putWord16BE :: Int -> Builder
putWord16BE n =
  word8 (fromIntegral ((n `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (n .&. 0xFF))

putWord32LE :: Word32 -> Builder
putWord32LE w =
  word8 (fromIntegral (w .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 24) .&. 0xFF))

-- | Encode a non-negative Int64 as a byuu-style varint.
putByuuVarint :: Int64 -> Builder
putByuuVarint = go
  where
    go v
      | v <= 0x7F = word8 (fromIntegral v .|. 0x80)
      | otherwise =
          let lo = fromIntegral (v .&. 0x7F) :: Word8
              v' = (v `shiftR` 7) - 1
          in word8 lo <> go v'

----------------------------------------------------------------------------
-- CRC-32 (standard reflected polynomial 0xEDB88320)
----------------------------------------------------------------------------

crc32 :: ByteString -> Word32
crc32 = complement . BS.foldl' step (complement 0)
  where
    step :: Word32 -> Word8 -> Word32
    step crc byte =
      let idx = fromIntegral ((crc `xor` fromIntegral byte) .&. 0xFF)
      in (crc `shiftR` 8) `xor` (crc32Table ! idx)

----------------------------------------------------------------------------
-- Bulk memory operations
----------------------------------------------------------------------------

-- | Bulk copy @len@ bytes from a ByteString (at @srcOff@) to a raw pointer
-- (at @dstOff@).  Uses memcpy internally.
copyBSRange :: Ptr Word8 -> Int -> ByteString -> Int -> Int -> IO ()
copyBSRange _   _      _   _      len | len <= 0 = pure ()
copyBSRange dst dstOff src srcOff len =
  BSU.unsafeUseAsCStringLen src $ \(srcPtr, _) ->
    copyBytes (dst `plusPtr` dstOff) (castPtr srcPtr `plusPtr` srcOff) len

----------------------------------------------------------------------------
-- CRC-16/IBM (reflected polynomial 0xA001, init 0x0000)
----------------------------------------------------------------------------

crc16 :: ByteString -> Word16
crc16 = BS.foldl' step 0
  where
    step :: Word16 -> Word8 -> Word16
    step crc byte =
      let idx = fromIntegral ((crc `xor` fromIntegral byte) .&. 0xFF)
      in (crc `shiftR` 8) `xor` (crc16Table ! idx)

crc16Table :: Array Word16 Word16
crc16Table = listArray (0, 255) [mkEntry i | i <- [0..255]]
  where
    mkEntry :: Word16 -> Word16
    mkEntry n = iterate step n !! 8
    step :: Word16 -> Word16
    step c
      | testBit c 0 = (c `shiftR` 1) `xor` 0xA001
      | otherwise    = c `shiftR` 1

----------------------------------------------------------------------------
-- Diff
----------------------------------------------------------------------------

-- | Find contiguous regions where two ByteStrings differ.
-- Merges nearby hunks (gap <= 5 bytes) to reduce record count.
-- Returns [(offset, changedBytes)] from the second ByteString.
diffHunks :: ByteString -> ByteString -> [(Int, ByteString)]
diffHunks old new = merge (go 0 ++ extension)
  where
    oldLen = BS.length old
    newLen = BS.length new
    minLen = min oldLen newLen
    extension
      | newLen > oldLen = [(oldLen, BS.drop oldLen new)]
      | otherwise       = []
    go i
      | i >= minLen = []
      | BS.index old i == BS.index new i = go (i + 1)
      | otherwise =
          let end = findEnd (i + 1)
          in (i, BS.take (end - i) (BS.drop i new)) : go end
    findEnd j
      | j >= minLen = minLen
      | BS.index old j /= BS.index new j = findEnd (j + 1)
      | otherwise = j
    merge [] = []
    merge [x] = [x]
    merge ((o1,d1):(o2,d2):rest)
      | o2 - o1 - BS.length d1 <= 5 =
          let merged = BS.take (o2 + BS.length d2 - o1) (BS.drop o1 new)
          in merge ((o1, merged) : rest)
      | otherwise = (o1,d1) : merge ((o2,d2):rest)

-- | Merge records whose gaps are ≤ gapThreshold bytes, filling from modBs.
-- Won't merge if the result exceeds maxMerged bytes (use maxBound for no limit).
mergeNearby :: Int -> Int -> ByteString -> [(Int, ByteString)] -> [(Int, ByteString)]
mergeNearby _ _ _ [] = []
mergeNearby _ _ _ [x] = [x]
mergeNearby gapThreshold maxMerged modBs ((off1, d1) : (off2, d2) : rest)
  | gap <= gapThreshold && mergedLen <= maxMerged =
      mergeNearby gapThreshold maxMerged modBs ((off1, merged) : rest)
  | otherwise = (off1, d1) : mergeNearby gapThreshold maxMerged modBs ((off2, d2) : rest)
  where
    end1 = off1 + BS.length d1
    gap  = off2 - end1
    fill = BS.take gap (BS.drop end1 modBs)
    merged = d1 <> fill <> d2
    mergedLen = BS.length merged

----------------------------------------------------------------------------
-- Additional builders
----------------------------------------------------------------------------

putWord16LE :: Word16 -> Builder
putWord16LE w =
  word8 (fromIntegral (w .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 8) .&. 0xFF))

putWord32BE :: Word32 -> Builder
putWord32BE w =
  word8 (fromIntegral (w `shiftR` 24))
  <> word8 (fromIntegral ((w `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (w .&. 0xFF))

putInt64BE :: Int64 -> Builder
putInt64BE w =
  word8 (fromIntegral (w `shiftR` 56))
  <> word8 (fromIntegral ((w `shiftR` 48) .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 40) .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 32) .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 24) .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((w `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (w .&. 0xFF))

crc32Table :: Array Word32 Word32
crc32Table = listArray (0, 255) [mkEntry i | i <- [0..255]]
  where
    mkEntry :: Word32 -> Word32
    mkEntry n = iterate step n !! 8
    step :: Word32 -> Word32
    step c
      | testBit c 0 = (c `shiftR` 1) `xor` 0xEDB88320
      | otherwise    = c `shiftR` 1
