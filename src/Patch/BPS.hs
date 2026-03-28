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

import Patch.Binary (getWord32LE, putWord32LE, putByuuVarint, copyByteStringRange)
import Patch.FFI (rustyCRC32, rustyBpsDiff)
import Patch.Get (Get, runGet, getBytes, byuuVarint, atEnd, failGet)
import Patch.Measure (Length(..), FileSize(..), Delta(..))
import Control.Monad (when)
import Patch.Format (showCRC, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), shiftR, testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word32)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

data BPSAction
  = SourceRead { sourceReadLength :: !Length }
  | TargetRead { targetReadPayload :: !ByteString }
  | SourceCopy { sourceCopyLength :: !Length, sourceCopyDelta :: !Delta }
  | TargetCopy { targetCopyLength :: !Length, targetCopyDelta :: !Delta }
  deriving (Show)

data BPSPatch = BPSPatch
  { bpsSourceSize :: !FileSize
  , bpsTargetSize :: !FileSize
  , bpsMetadata   :: ByteString
  , bpsActions    :: [BPSAction]
  , bpsSourceCRC  :: Word32
  , bpsTargetCRC  :: Word32
  , bpsPatchCRC   :: Word32
  } deriving (Show)

parseBPS :: ByteString -> Either String BPSPatch
parseBPS input
  | ByteString.length input < 4 = Left "BPS: input too short"
  | ByteString.take 4 input /= "BPS1" = Left "not a BPS file (bad magic)"
  | ByteString.length input < 12 = Left "BPS: truncated footer"
  | otherwise = do
      -- Validate patch CRC (covers everything except the last 4 bytes)
      let storedPatchCRC = getWord32LE (ByteString.length input - 4) input
          actualPatchCRC = rustyCRC32 (ByteString.take (ByteString.length input - 4) input)
      if storedPatchCRC /= actualPatchCRC
        then Left ("BPS: patch CRC mismatch (stored " ++ showCRC storedPatchCRC
                    ++ ", computed " ++ showCRC actualPatchCRC ++ ")")
        else pure ()
      let sourceCRC = getWord32LE (ByteString.length input - 12) input
          targetCRC = getWord32LE (ByteString.length input - 8)  input
          -- Parse body between magic and footer using Get monad
          bodyBytes = ByteString.take (ByteString.length input - 16) (ByteString.drop 4 input)
      (sourceSize, targetSize, metadata, actions) <- runGet parseBPSBody bodyBytes
      Right BPSPatch
        { bpsSourceSize = sourceSize
        , bpsTargetSize = targetSize
        , bpsMetadata   = metadata
        , bpsActions    = actions
        , bpsSourceCRC  = sourceCRC
        , bpsTargetCRC  = targetCRC
        , bpsPatchCRC   = storedPatchCRC
        }

parseBPSBody :: Get (FileSize, FileSize, ByteString, [BPSAction])
parseBPSBody = do
  rawSourceSize <- byuuVarint
  rawTargetSize <- byuuVarint
  when (rawSourceSize < 0) $ failGet "BPS: negative source size"
  when (rawTargetSize < 0) $ failGet "BPS: negative target size"
  let sourceSize = FileSize rawSourceSize
      targetSize = FileSize rawTargetSize
  metadataLength <- fromIntegral <$> byuuVarint
  metadata       <- getBytes (Length metadataLength)
  actions <- parseActions
  pure (sourceSize, targetSize, metadata, actions)

parseActions :: Get [BPSAction]
parseActions = do
  done <- atEnd
  if done then pure []
  else do
    encoded <- byuuVarint
    let commandCode = encoded .&. 3
        dataLength = fromIntegral (shiftR encoded 2) + 1
    action <- case commandCode of
      0 -> pure (SourceRead (Length dataLength))
      1 -> TargetRead <$> getBytes (Length dataLength)
      2 -> SourceCopy (Length dataLength) . Delta . decodeSignedVarint <$> byuuVarint
      3 -> TargetCopy (Length dataLength) . Delta . decodeSignedVarint <$> byuuVarint
      _ -> error "unreachable"  -- (.&. 3) is always 0-3; GHC can't see this
    remaining <- parseActions
    pure (action : remaining)

-- Decode a signed varint: bit 0 = sign (1 = negative), bits 1+ = magnitude.
decodeSignedVarint :: Int64 -> Int64
decodeSignedVarint encoded =
  let magnitude = shiftR encoded 1
  in if testBit encoded 0 then negate magnitude else magnitude

-- Caller validates checksums.
applyBPS :: BPSPatch -> ByteString -> Either String ByteString
applyBPS patch source = Right $ unsafeCreate targetLength $ \outputPointer ->
  applyLoop outputPointer 0 0 0 (bpsActions patch)
  where
    targetLength = fromIntegral (unFileSize (bpsTargetSize patch))
    sourceLength = ByteString.length source

    applyLoop :: Ptr Word8 -> Int -> Int64 -> Int64 -> [BPSAction] -> IO ()
    applyLoop _             _              _              _              []           = pure ()
    applyLoop outputPointer outputPosition sourceRelative targetRelative (action:remaining) = case action of
      SourceRead actionLength -> do
        let copyLength = unLength actionLength
            count = min copyLength (targetLength - outputPosition)
            inBounds = max 0 (min count (sourceLength - outputPosition))
        copyByteStringRange outputPointer outputPosition source outputPosition inBounds
        when (inBounds < count) $
          fillBytes (outputPointer `plusPtr` (outputPosition + inBounds)) 0 (count - inBounds)
        applyLoop outputPointer (outputPosition + count) sourceRelative targetRelative remaining

      TargetRead payload -> do
        let count = min (ByteString.length payload) (targetLength - outputPosition)
        copyByteStringRange outputPointer outputPosition payload 0 count
        applyLoop outputPointer (outputPosition + count) sourceRelative targetRelative remaining

      SourceCopy actionLength actionDelta -> do
        let copyLength = unLength actionLength
            nextSourceRelative = sourceRelative + unDelta actionDelta
            sourceOffset  = fromIntegral nextSourceRelative :: Int
            count   = min copyLength (targetLength - outputPosition)
            -- Clamp to the portion that falls within the source ByteString
            leadingClipLength = max 0 (negate sourceOffset)
            safeSourceStart   = max 0 sourceOffset
            safeSourceLength  = max 0 (min (count - leadingClipLength) (sourceLength - safeSourceStart))
        -- Zero-fill any leading out-of-bounds bytes
        when (leadingClipLength > 0) $
          fillBytes (outputPointer `plusPtr` outputPosition) 0 (min leadingClipLength count)
        -- Bulk copy the in-bounds portion
        copyByteStringRange outputPointer (outputPosition + leadingClipLength) source safeSourceStart safeSourceLength
        -- Zero-fill any trailing out-of-bounds bytes
        let copied = leadingClipLength + safeSourceLength
        when (copied < count) $
          fillBytes (outputPointer `plusPtr` (outputPosition + copied)) 0 (count - copied)
        applyLoop outputPointer (outputPosition + count) (nextSourceRelative + fromIntegral count) targetRelative remaining

      TargetCopy actionLength actionDelta -> do
        let copyLength = unLength actionLength
            nextTargetRelative = targetRelative + unDelta actionDelta
            count   = min copyLength (targetLength - outputPosition)
            readOffset = fromIntegral nextTargetRelative
        -- Byte-by-byte: source region may overlap with destination
        mapM_ (\index -> do
          let readIndex = readOffset + index
          byte <- if readIndex >= 0 && readIndex < targetLength
               then peekByteOff outputPointer readIndex :: IO Word8
               else pure 0
          pokeByteOff outputPointer (outputPosition + index) byte) [0..count-1]
        applyLoop outputPointer (outputPosition + count) sourceRelative (nextTargetRelative + fromIntegral count) remaining

bpsMeta :: BPSPatch -> [(String, String)]
bpsMeta patch = concat
  [ [("source size", show (unFileSize (bpsSourceSize patch)))]
  , [("target size", show (unFileSize (bpsTargetSize patch)))]
  , [("metadata", metadataDisplay)]
  , [("source CRC", showCRC (bpsSourceCRC patch))]
  , [("target CRC", showCRC (bpsTargetCRC patch))]
  , [("patch CRC", showCRC (bpsPatchCRC patch))]
  ]
  where
    metadata = bpsMetadata patch
    metadataDisplay
      | ByteString.null metadata = "(none)"
      | otherwise        = show (ByteString.length metadata) ++ " bytes: "
                        ++ map sanitize (ByteString8.unpack (ByteString.take 200 metadata))
                        ++ if ByteString.length metadata > 200 then "..." else ""
    sanitize character
      | character >= ' ' && character <= '~' = character
      | otherwise                            = '.'

bpsInfo :: BPSPatch -> String
bpsInfo patch = unlines $ filter (not . null) $
  [ "format:      BPS" ]
  ++ map renderField (bpsMeta patch)
  ++ [ "actions:     " ++ show (length (bpsActions patch)) ]

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a BPS patch using the Rust suffix-array diff engine.
createBPS :: ByteString -> ByteString -> ByteString -> ByteString
createBPS original modified metadata =
  let sourceCRC = rustyCRC32 original
      targetCRC = rustyCRC32 modified
      actionBytes = rustyBpsDiff original modified
      body = byteString "BPS1"
             <> putByuuVarint (fromIntegral (ByteString.length original))
             <> putByuuVarint (fromIntegral (ByteString.length modified))
             <> putByuuVarint (fromIntegral (ByteString.length metadata))
             <> byteString metadata
             <> byteString actionBytes
             <> putWord32LE sourceCRC
             <> putWord32LE targetCRC
      bodyBytes = LazyByteString.toStrict (toLazyByteString body)
      patchCRC = rustyCRC32 bodyBytes
  in bodyBytes <> LazyByteString.toStrict (toLazyByteString (putWord32LE patchCRC))
