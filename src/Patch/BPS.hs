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

import Patch.Binary (getWord32LE, putWord32LE, putByuuVarint, copyBSRange)
import Patch.FFI (rustyCRC32, rustyBpsDiff)
import Patch.Get (Get, runGet, getBytes, byuuVarint, atEnd, failGet)
import Control.Monad (when)
import Patch.Format (showCRC, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), shiftR, testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word32)
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
          actualPatchCRC = rustyCRC32 (BS.take (BS.length bs - 4) bs)
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

-- | Create a BPS patch using the Rust suffix-array diff engine.
createBPS :: ByteString -> ByteString -> ByteString -> ByteString
createBPS orig modified metadata =
  let srcCRC = rustyCRC32 orig
      tgtCRC = rustyCRC32 modified
      actionBytes = rustyBpsDiff orig modified
      body = byteString "BPS1"
             <> putByuuVarint (fromIntegral (BS.length orig))
             <> putByuuVarint (fromIntegral (BS.length modified))
             <> putByuuVarint (fromIntegral (BS.length metadata))
             <> byteString metadata
             <> byteString actionBytes
             <> putWord32LE srcCRC
             <> putWord32LE tgtCRC
      bodyBs = BL.toStrict (toLazyByteString body)
      patchCRC = rustyCRC32 bodyBs
  in bodyBs <> BL.toStrict (toLazyByteString (putWord32LE patchCRC))
