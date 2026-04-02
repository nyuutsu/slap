{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Parse
  ( parseBPS
  , parseBPSBody
  , parseActions
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..), decodeSignedVarint)
import Slap.Binary (getWord32LE)
import Slap.Checksum (CRC32(..), showCRC32)
import Slap.FFI (rustyCRC32)
import Slap.Get (Get, runGet, getBytes, byuuVarint, atEnd, failGet)
import Slap.Measure (Length(..), FileSize(..), Delta(..))

import Control.Monad (when)
import Data.Bits ((.&.), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

parseBPS :: ByteString -> Either String BPSPatch
parseBPS input
  | ByteString.length input < 4 = Left "BPS: input too short"
  | ByteString.take 4 input /= "BPS1" = Left "not a BPS file (bad magic)"
  | ByteString.length input < 12 = Left "BPS: truncated footer"
  | otherwise = do
      -- Validate patch CRC (covers everything except the last 4 bytes)
      let storedPatchCRC = CRC32 (getWord32LE (ByteString.length input - 4) input)
          actualPatchCRC = rustyCRC32 (ByteString.take (ByteString.length input - 4) input)
      if storedPatchCRC /= actualPatchCRC
        then Left ("BPS: patch CRC mismatch (stored " ++ showCRC32 storedPatchCRC
                    ++ ", computed " ++ showCRC32 actualPatchCRC ++ ")")
        else pure ()
      let sourceCRC = CRC32 (getWord32LE (ByteString.length input - 12) input)
          targetCRC = CRC32 (getWord32LE (ByteString.length input - 8)  input)
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
