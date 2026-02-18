{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.BPS
  ( BPSAction(..)
  , BPSPatch(..)
  , parseBPS
  , applyBPS
  , createBPS
  , bpsInfo
  ) where

import Patch.Binary (getByuuVarint, getWord32LE, putWord32LE, putByuuVarint, crc32, copyBSRange)
import Patch.Format (showCRC)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), shiftL, shiftR, (.|.), testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff, pokeByteOff)

data BPSAction
  = SourceRead Int           -- length (implicit: read from source at output offset)
  | TargetRead ByteString    -- literal data
  | SourceCopy Int Int64     -- length, signed offset delta
  | TargetCopy Int Int64     -- length, signed offset delta
  deriving (Show)

data BPSPatch = BPSPatch
  { bpsSourceSize :: Int64
  , bpsTargetSize :: Int64
  , bpsMetadata   :: ByteString
  , bpsActions    :: [BPSAction]
  , bpsSourceCRC  :: Word32
  , bpsTargetCRC  :: Word32
  , bpsPatchCRC   :: Word32
  } deriving (Show)

-- | Parse a BPS patch from raw bytes.
parseBPS :: ByteString -> Either String BPSPatch
parseBPS bs
  | BS.length bs < 4 = Left "too short for BPS header"
  | BS.take 4 bs /= "BPS1" = Left "not a BPS file (bad magic)"
  | BS.length bs < 12 = Left "truncated BPS footer"
  | otherwise = do
      -- Validate patch CRC (covers everything except the last 4 bytes)
      let storedPatchCRC = getWord32LE (BS.length bs - 4) bs
          actualPatchCRC = crc32 (BS.take (BS.length bs - 4) bs)
      if storedPatchCRC /= actualPatchCRC
        then Left ("patch CRC mismatch (stored " ++ showCRC storedPatchCRC
                    ++ ", computed " ++ showCRC actualPatchCRC ++ ")")
        else pure ()
      let (srcSize, n1) = getByuuVarint 4 bs
          (tgtSize, n2) = getByuuVarint (4 + n1) bs
          (metaLen, n3) = getByuuVarint (4 + n1 + n2) bs
          metaOff       = 4 + n1 + n2 + n3
          meta          = BS.take (fromIntegral metaLen) (BS.drop metaOff bs)
          actionsStart  = metaOff + fromIntegral metaLen
          actionsEnd    = BS.length bs - 12  -- 3 * CRC32
          actionsBs     = BS.take (actionsEnd - actionsStart) (BS.drop actionsStart bs)
          actions       = parseActions actionsBs
          srcCRC        = getWord32LE (BS.length bs - 12) bs
          tgtCRC        = getWord32LE (BS.length bs - 8) bs
      Right BPSPatch
        { bpsSourceSize = srcSize
        , bpsTargetSize = tgtSize
        , bpsMetadata   = meta
        , bpsActions    = actions
        , bpsSourceCRC  = srcCRC
        , bpsTargetCRC  = tgtCRC
        , bpsPatchCRC   = storedPatchCRC
        }

parseActions :: ByteString -> [BPSAction]
parseActions bs = go 0
  where
    go pos
      | pos >= BS.length bs = []
      | otherwise =
          let (raw, n) = getByuuVarint pos bs
              cmd      = raw .&. 3
              len      = fromIntegral (shiftR raw 2) + 1
              pos'     = pos + n
          in case cmd of
               0 -> SourceRead len : go pos'
               1 -> let dat = BS.take len (BS.drop pos' bs)
                    in TargetRead dat : go (pos' + len)
               2 -> let (rawOff, n2) = getByuuVarint pos' bs
                        signedOff = decodeSignedVarint rawOff
                    in SourceCopy len signedOff : go (pos' + n2)
               3 -> let (rawOff, n2) = getByuuVarint pos' bs
                        signedOff = decodeSignedVarint rawOff
                    in TargetCopy len signedOff : go (pos' + n2)
               _ -> go pos'  -- impossible, but satisfy exhaustiveness

-- Decode a signed varint: bit 0 = sign (1 = negative), bits 1+ = magnitude.
decodeSignedVarint :: Int64 -> Int64
decodeSignedVarint v =
  let magnitude = shiftR v 1
  in if testBit v 0 then negate magnitude else magnitude

-- | Apply a BPS patch.  The caller validates checksums; this just applies.
applyBPS :: BPSPatch -> ByteString -> Either String ByteString
applyBPS patch source = Right $ unsafeCreate tgtLen $ \ptr ->
  go ptr 0 0 0 (bpsActions patch)
  where
    tgtLen = fromIntegral (bpsTargetSize patch)
    srcLen = BS.length source

    readSrc :: Int -> Word8
    readSrc i
      | i < srcLen = BS.index source i
      | otherwise  = 0

    go :: Ptr Word8 -> Int -> Int64 -> Int64 -> [BPSAction] -> IO ()
    go _   _      _      _      []           = pure ()
    go ptr outPos srcRel tgtRel (action:rest) = case action of
      SourceRead len -> do
        let count = min len (tgtLen - outPos)
        mapM_ (\i -> pokeByteOff ptr (outPos + i) (readSrc (outPos + i))) [0..count-1]
        go ptr (outPos + count) srcRel tgtRel rest

      TargetRead dat -> do
        let count = min (BS.length dat) (tgtLen - outPos)
        copyBSRange ptr outPos dat 0 count
        go ptr (outPos + count) srcRel tgtRel rest

      SourceCopy len delta -> do
        let srcRel' = srcRel + delta
            count   = min len (tgtLen - outPos)
        mapM_ (\i -> pokeByteOff ptr (outPos + i) (readSrc (fromIntegral srcRel' + i))) [0..count-1]
        go ptr (outPos + count) (srcRel' + fromIntegral count) tgtRel rest

      TargetCopy len delta -> do
        let tgtRel' = tgtRel + delta
            count   = min len (tgtLen - outPos)
        -- Byte-by-byte: source region may overlap with destination
        mapM_ (\i -> do
          b <- peekByteOff ptr (fromIntegral tgtRel' + i) :: IO Word8
          pokeByteOff ptr (outPos + i) b) [0..count-1]
        go ptr (outPos + count) srcRel (tgtRel' + fromIntegral count) rest

-- | Human-readable summary of a BPS patch.
bpsInfo :: BPSPatch -> String
bpsInfo p = unlines $ filter (not . null)
  [ "format:      BPS"
  , "source size: " ++ show (bpsSourceSize p)
  , "target size: " ++ show (bpsTargetSize p)
  , metaStr
  , "actions:     " ++ show (length (bpsActions p))
  , "source CRC:  " ++ showCRC (bpsSourceCRC p)
  , "target CRC:  " ++ showCRC (bpsTargetCRC p)
  , "patch CRC:   " ++ showCRC (bpsPatchCRC p)
  ]
  where
    metaStr
      | BS.null (bpsMetadata p) = ""
      | otherwise = "metadata:    " ++ show (BS.length (bpsMetadata p)) ++ " bytes"

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a BPS patch (linear mode: SourceRead + TargetRead only).
createBPS :: ByteString -> ByteString -> ByteString
createBPS orig modified =
  let srcCRC = crc32 orig
      tgtCRC = crc32 modified
      actions = bpsDiff orig modified
      body = byteString "BPS1"
             <> putByuuVarint (fromIntegral (BS.length orig))
             <> putByuuVarint (fromIntegral (BS.length modified))
             <> putByuuVarint 0  -- no metadata
             <> foldMap encodeBPSAction actions
             <> putWord32LE srcCRC
             <> putWord32LE tgtCRC
      bodyBs = BL.toStrict (toLazyByteString body)
      patchCRC = crc32 bodyBs
  in bodyBs <> BL.toStrict (toLazyByteString (putWord32LE patchCRC))

encodeBPSAction :: BPSAction -> Builder
encodeBPSAction (SourceRead len) =
  putByuuVarint (fromIntegral ((len - 1) `shiftL` 2 .|. 0))
encodeBPSAction (TargetRead dat) =
  putByuuVarint (fromIntegral ((BS.length dat - 1) `shiftL` 2 .|. 1))
  <> byteString dat
encodeBPSAction (SourceCopy len delta) =
  putByuuVarint (fromIntegral ((len - 1) `shiftL` 2 .|. 2))
  <> encodeSignedVarint delta
encodeBPSAction (TargetCopy len delta) =
  putByuuVarint (fromIntegral ((len - 1) `shiftL` 2 .|. 3))
  <> encodeSignedVarint delta

encodeSignedVarint :: Int64 -> Builder
encodeSignedVarint v =
  let magnitude = abs v
      encoded = (magnitude `shiftL` 1) .|. (if v < 0 then 1 else 0)
  in putByuuVarint encoded

-- | Linear diff: SourceRead for matching runs, TargetRead for differences.
bpsDiff :: ByteString -> ByteString -> [BPSAction]
bpsDiff orig modified = go 0
  where
    srcLen = BS.length orig
    tgtLen = BS.length modified

    go i
      | i >= tgtLen = []
      | i < srcLen && BS.index orig i == BS.index modified i =
          let end = matchEnd i
              len = end - i
          in SourceRead len : go end
      | otherwise =
          let end = diffEnd i
              dat = BS.take (end - i) (BS.drop i modified)
          in TargetRead dat : go end

    matchEnd i
      | i >= tgtLen = tgtLen
      | i >= srcLen = i
      | BS.index orig i == BS.index modified i = matchEnd (i + 1)
      | otherwise = i

    diffEnd i
      | i >= tgtLen = tgtLen
      | i >= srcLen = tgtLen  -- everything beyond source is a diff
      | BS.index orig i /= BS.index modified i = diffEnd (i + 1)
      | otherwise = i

