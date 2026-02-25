{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.BPS
  ( BPSAction(..)
  , BPSPatch(..)
  , parseBPS
  , applyBPS
  , createBPS
  , bpsMeta
  , bpsInfo
  ) where

-- Canonical reference: https://github.com/blakesmith/rombp/blob/master/docs/bps_spec.md (byuu BPS spec)

import Patch.Binary (getWord32LE, putWord32LE, putByuuVarint, crc32, copyBSRange)
import Patch.Get (Get, runGet, getBytes, byuuVarint, atEnd, failGet)
import Control.Monad (when)
import Patch.Format (showCRC, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), shiftL, shiftR, (.|.), testBit, xor)
import Data.Int (Int64)
import Data.Word (Word8, Word32, Word64)
import qualified Data.IntMap.Strict as IM
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
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

parseBPS :: ByteString -> Either String BPSPatch
parseBPS bs
  | BS.length bs < 4 = Left "BPS: input too short"
  | BS.take 4 bs /= "BPS1" = Left "not a BPS file (bad magic)"
  | BS.length bs < 12 = Left "BPS: truncated footer"
  | otherwise = do
      -- Validate patch CRC (covers everything except the last 4 bytes)
      let storedPatchCRC = getWord32LE (BS.length bs - 4) bs
          actualPatchCRC = crc32 (BS.take (BS.length bs - 4) bs)
      if storedPatchCRC /= actualPatchCRC
        then Left ("BPS: patch CRC mismatch (stored " ++ showCRC storedPatchCRC
                    ++ ", computed " ++ showCRC actualPatchCRC ++ ")")
        else pure ()
      let srcCRC = getWord32LE (BS.length bs - 12) bs
          tgtCRC = getWord32LE (BS.length bs - 8)  bs
          -- Parse body between magic and footer using Get monad
          bodyBs = BS.take (BS.length bs - 16) (BS.drop 4 bs)
      (srcSize, tgtSize, meta, actions) <- runGet parseBPSBody bodyBs
      Right BPSPatch
        { bpsSourceSize = srcSize
        , bpsTargetSize = tgtSize
        , bpsMetadata   = meta
        , bpsActions    = actions
        , bpsSourceCRC  = srcCRC
        , bpsTargetCRC  = tgtCRC
        , bpsPatchCRC   = storedPatchCRC
        }

parseBPSBody :: Get (Int64, Int64, ByteString, [BPSAction])
parseBPSBody = do
  srcSize <- byuuVarint
  tgtSize <- byuuVarint
  when (srcSize < 0) $ failGet "BPS: negative source size"
  when (tgtSize < 0) $ failGet "BPS: negative target size"
  metaLen <- fromIntegral <$> byuuVarint
  meta    <- getBytes metaLen
  actions <- parseActions
  pure (srcSize, tgtSize, meta, actions)

parseActions :: Get [BPSAction]
parseActions = do
  done <- atEnd
  if done then pure []
  else do
    raw <- byuuVarint
    let cmd = raw .&. 3
        len = fromIntegral (shiftR raw 2) + 1
    action <- case cmd of
      0 -> pure (SourceRead len)
      1 -> TargetRead <$> getBytes len
      2 -> SourceCopy len . decodeSignedVarint <$> byuuVarint
      3 -> TargetCopy len . decodeSignedVarint <$> byuuVarint
      _ -> error "unreachable"  -- (.&. 3) is always 0-3; GHC can't see this
    rest <- parseActions
    pure (action : rest)

-- Decode a signed varint: bit 0 = sign (1 = negative), bits 1+ = magnitude.
decodeSignedVarint :: Int64 -> Int64
decodeSignedVarint v =
  let magnitude = shiftR v 1
  in if testBit v 0 then negate magnitude else magnitude

-- Caller validates checksums.
applyBPS :: BPSPatch -> ByteString -> Either String ByteString
applyBPS patch source = Right $ unsafeCreate tgtLen $ \ptr ->
  go ptr 0 0 0 (bpsActions patch)
  where
    tgtLen = fromIntegral (bpsTargetSize patch)
    srcLen = BS.length source

    go :: Ptr Word8 -> Int -> Int64 -> Int64 -> [BPSAction] -> IO ()
    go _   _      _      _      []           = pure ()
    go ptr outPos srcRel tgtRel (action:rest) = case action of
      SourceRead len -> do
        let count = min len (tgtLen - outPos)
            inBounds = max 0 (min count (srcLen - outPos))
        copyBSRange ptr outPos source outPos inBounds
        when (inBounds < count) $
          fillBytes (ptr `plusPtr` (outPos + inBounds)) 0 (count - inBounds)
        go ptr (outPos + count) srcRel tgtRel rest

      TargetRead dat -> do
        let count = min (BS.length dat) (tgtLen - outPos)
        copyBSRange ptr outPos dat 0 count
        go ptr (outPos + count) srcRel tgtRel rest

      SourceCopy len delta -> do
        let srcRel' = srcRel + delta
            srcOff  = fromIntegral srcRel' :: Int
            count   = min len (tgtLen - outPos)
            -- Clamp to the portion that falls within the source ByteString
            clipStart = max 0 (negate srcOff)
            inStart   = max 0 srcOff
            inBounds  = max 0 (min (count - clipStart) (srcLen - inStart))
        -- Zero-fill any leading out-of-bounds bytes
        when (clipStart > 0) $
          fillBytes (ptr `plusPtr` outPos) 0 (min clipStart count)
        -- Bulk copy the in-bounds portion
        copyBSRange ptr (outPos + clipStart) source inStart inBounds
        -- Zero-fill any trailing out-of-bounds bytes
        let copied = clipStart + inBounds
        when (copied < count) $
          fillBytes (ptr `plusPtr` (outPos + copied)) 0 (count - copied)
        go ptr (outPos + count) (srcRel' + fromIntegral count) tgtRel rest

      TargetCopy len delta -> do
        let tgtRel' = tgtRel + delta
            count   = min len (tgtLen - outPos)
            readOff = fromIntegral tgtRel'
        -- Byte-by-byte: source region may overlap with destination
        mapM_ (\i -> do
          let ri = readOff + i
          b <- if ri >= 0 && ri < tgtLen
               then peekByteOff ptr ri :: IO Word8
               else pure 0
          pokeByteOff ptr (outPos + i) b) [0..count-1]
        go ptr (outPos + count) srcRel (tgtRel' + fromIntegral count) rest

bpsMeta :: BPSPatch -> [(String, String)]
bpsMeta p = concat
  [ [("source size", show (bpsSourceSize p))]
  , [("target size", show (bpsTargetSize p))]
  , [("metadata", metaStr)]
  , [("source CRC", showCRC (bpsSourceCRC p))]
  , [("target CRC", showCRC (bpsTargetCRC p))]
  , [("patch CRC", showCRC (bpsPatchCRC p))]
  ]
  where
    meta = bpsMetadata p
    metaStr
      | BS.null meta = "(none)"
      | otherwise    = show (BS.length meta) ++ " bytes: "
                    ++ map sanitize (BS8.unpack (BS.take 200 meta))
                    ++ if BS.length meta > 200 then "..." else ""
    sanitize c
      | c >= ' ' && c <= '~' = c
      | otherwise             = '.'

bpsInfo :: BPSPatch -> String
bpsInfo p = unlines $ filter (not . null) $
  [ "format:      BPS" ]
  ++ map renderField (bpsMeta p)
  ++ [ "actions:     " ++ show (length (bpsActions p)) ]

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a BPS patch using rolling-hash matching.
createBPS :: ByteString -> ByteString -> ByteString -> ByteString
createBPS orig modified metadata =
  let srcCRC = crc32 orig
      tgtCRC = crc32 modified
      actions = bpsDiff orig modified
      body = byteString "BPS1"
             <> putByuuVarint (fromIntegral (BS.length orig))
             <> putByuuVarint (fromIntegral (BS.length modified))
             <> putByuuVarint (fromIntegral (BS.length metadata))
             <> byteString metadata
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

----------------------------------------------------------------------------
-- Rolling-hash diff
----------------------------------------------------------------------------

-- Window size for hash matching.
diffWindow :: Int
diffWindow = 16

-- Maximum candidates to check per hash bucket.
diffMaxCands :: Int
diffMaxCands = 8

-- FNV-1a hash of diffWindow bytes starting at off.
hashW :: ByteString -> Int -> Int
hashW bs off = fromIntegral (scan off 14695981039346656037)
  where
    !end = off + diffWindow
    scan :: Int -> Word64 -> Word64
    scan !i !h
      | i >= end  = h
      | otherwise = scan (i + 1) ((h `xor` fromIntegral (BS.index bs i)) * 1099511628211)

-- Stride for index building.  Dense for small files, sampled for large ones.
-- With stride S, matches starting at non-S-aligned source offsets are still
-- found (at most S-1 bytes later), losing at most S-1 literal bytes per match.
indexStride :: Int -> Int
indexStride len
  | len <= 0x40000   = 1   -- <= 256 KB: every byte
  | len <= 0x1000000 = 4   -- <= 16 MB: every 4th byte
  | otherwise        = 16  -- > 16 MB: every 16th byte

-- Build hash -> [offset] index, strided for large inputs.
buildHashIndex :: ByteString -> IM.IntMap [Int]
buildHashIndex bs
  | len < diffWindow = IM.empty
  | otherwise = foldl' ins IM.empty [0, stride .. len - diffWindow]
  where
    len    = BS.length bs
    stride = indexStride len
    ins !m i = IM.insertWith (++) (hashW bs i) [i] m

-- Count matching bytes between a[aOff..] and b[bOff..].
extendFwd :: ByteString -> Int -> ByteString -> Int -> Int
extendFwd a aOff b bOff = scan 0
  where
    !limit = min (BS.length a - aOff) (BS.length b - bOff)
    scan :: Int -> Int
    scan !n
      | n >= limit = n
      | BS.index a (aOff + n) == BS.index b (bOff + n) = scan (n + 1)
      | otherwise  = n

-- Cost of a byuu-style varint encoding (in bytes).
byuuVarintCost :: Int64 -> Int
byuuVarintCost v
  | v <= 0x7F = 1
  | otherwise = 1 + byuuVarintCost (shiftR v 7 - 1)

-- Encoded size of a SourceCopy/TargetCopy action (length varint + delta varint).
copyActionCost :: Int -> Int64 -> Int
copyActionCost len delta = byuuVarintCost (fromIntegral (shiftL (len - 1) 2 .|. 2))
                         + byuuVarintCost signedEnc
  where
    magnitude = abs delta
    signedEnc = shiftL magnitude 1 .|. (if delta < 0 then 1 else 0)

-- | Rolling-hash diff: emits SourceRead, TargetRead, SourceCopy, TargetCopy.
bpsDiff :: ByteString -> ByteString -> [BPSAction]
bpsDiff src tgt
  | tgtLen == 0 = []
  | otherwise   = walk 0 0 0 (-1)
  where
    !srcLen = BS.length src
    !tgtLen = BS.length tgt
    srcIdx  = buildHashIndex src
    tgtIdx  = buildHashIndex tgt

    -- pendStart < 0 means no pending literals; >= 0 means literals from
    -- pendStart to outPos-1 waiting to be flushed as TargetRead.
    walk :: Int -> Int64 -> Int64 -> Int -> [BPSAction]
    walk !outPos !srcRel !tgtRel !pend
      | outPos >= tgtLen = flushP pend outPos []

      -- SourceRead: lockstep match at current position
      | outPos < srcLen, BS.index src outPos == BS.index tgt outPos =
          let !len     = srLen outPos
              !outPos' = outPos + len
          in flushP pend outPos (SourceRead len : walk outPos' srcRel tgtRel (-1))

      -- Hash-based copy match
      | outPos + diffWindow <= tgtLen
      , Just (act, len, srcRel', tgtRel') <- findCopy outPos srcRel tgtRel =
          let !outPos' = outPos + len
          in flushP pend outPos (act : walk outPos' srcRel' tgtRel' (-1))

      -- Accumulate literal byte
      | otherwise =
          walk (outPos + 1) srcRel tgtRel (if pend < 0 then outPos else pend)

    flushP :: Int -> Int -> [BPSAction] -> [BPSAction]
    flushP pend outPos rest
      | pend < 0  = rest
      | otherwise = TargetRead (BS.take (outPos - pend) (BS.drop pend tgt)) : rest

    -- Count SourceRead length starting at i (caller verified first byte matches).
    srLen :: Int -> Int
    srLen start = scan start
      where
        !lim = min srcLen tgtLen
        scan :: Int -> Int
        scan !j
          | j >= lim                          = j - start
          | BS.index src j == BS.index tgt j = scan (j + 1)
          | otherwise                         = j - start

    -- Find the best SourceCopy or TargetCopy at outPos.
    -- Returns (action, matchLen, newSrcRel, newTgtRel).
    findCopy :: Int -> Int64 -> Int64 -> Maybe (BPSAction, Int, Int64, Int64)
    findCopy outPos srcRel tgtRel = pickBetter srcOpt tgtOpt
      where
        !h = hashW tgt outPos

        srcOpt = do
          (len, off) <- bestCandidate src (IM.findWithDefault [] h srcIdx)
          let !delta = fromIntegral off - srcRel
          if copyActionCost len delta < len
            then Just (SourceCopy len delta, len,
                       fromIntegral off + fromIntegral len, tgtRel)
            else Nothing

        tgtOpt = do
          (len, off) <- bestCandidate tgt
                          (filter (< outPos) (IM.findWithDefault [] h tgtIdx))
          let !delta = fromIntegral off - tgtRel
          if copyActionCost len delta < len
            then Just (TargetCopy len delta, len,
                       srcRel, fromIntegral off + fromIntegral len)
            else Nothing

        bestCandidate ref cands =
          case [ (len, c)
               | c <- take diffMaxCands cands
               , let len = extendFwd ref c tgt outPos
               , len >= diffWindow
               ] of
            []   -> Nothing
            x:xs -> Just (foldl' pick x xs)
          where pick a@(la,_) b@(lb,_) = if lb > la then b else a

        pickBetter Nothing  Nothing  = Nothing
        pickBetter (Just s) Nothing  = Just s
        pickBetter Nothing  (Just t) = Just t
        pickBetter (Just s@(_,sl,_,_)) (Just t@(_,tl,_,_))
          | sl >= tl  = Just s
          | otherwise = Just t

