{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.BSDiff
  ( BSDiffPatch(..)
  , BSDiffControl(..)
  , parseBSDiff
  , applyBSDiff
  , bsdiffMeta
  , bsdiffInfo
  ) where

-- Canonical reference: bsdiff 4.3 source (Colin Percival)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Patch.Binary (copyByteStringRange)
import Patch.Compress (bz2Decompress)
import Patch.Measure (FileSize(..), Delta(..))
import Patch.Format (renderField)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (pokeByteOff)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data BSDiffPatch = BSDiffPatch
  { bsdiffControlSize :: !FileSize   -- compressed control block size
  , bsdiffDiffSize    :: !FileSize   -- compressed diff block size
  , bsdiffExtraSize   :: !FileSize   -- compressed extra block size
  , bsdiffTargetSize  :: !FileSize   -- target file size
  , bsdiffControls    :: [BSDiffControl]
  , bsdiffDiffData    :: ByteString  -- decompressed diff stream
  , bsdiffExtraData   :: ByteString  -- decompressed extra stream
  } deriving (Show)

data BSDiffControl = BSDiffControl
  { controlAdd  :: !Int64  -- bytes to add from diff stream to source
  , controlCopy :: !Int64  -- bytes to copy from extra stream
  , controlSeek :: !Delta  -- signed seek offset in source
  } deriving (Show)

----------------------------------------------------------------------------
-- Signed LE64 (bsdiff sign-magnitude encoding)
----------------------------------------------------------------------------

-- | Read a signed 64-bit LE value in bsdiff format.
-- Bit 63 of byte 7 is the sign; lower 63 bits are the magnitude (LE).
getSignMagnitude64 :: Int -> ByteString -> Int64
getSignMagnitude64 offset input =
  let readByte index = fromIntegral (ByteString.index input (offset + index)) :: Int64
      magnitude = readByte 0 .|. (readByte 1 `shiftL` 8) .|. (readByte 2 `shiftL` 16) .|. (readByte 3 `shiftL` 24)
                  .|. (readByte 4 `shiftL` 32) .|. (readByte 5 `shiftL` 40) .|. (readByte 6 `shiftL` 48)
                  .|. ((readByte 7 .&. 0x7F) `shiftL` 56)
  in if testBit (ByteString.index input (offset + 7)) 7
     then negate magnitude
     else magnitude

----------------------------------------------------------------------------
-- Safe decompression
----------------------------------------------------------------------------

safeDecompressBZip :: String -> ByteString -> Either String ByteString
safeDecompressBZip _     compressed | ByteString.null compressed = Right ByteString.empty
safeDecompressBZip label compressed = case bz2Decompress compressed of
  Left _  -> Left ("BSDiff: " ++ label ++ " decompression failed")
  Right decompressed -> Right decompressed

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseBSDiff :: ByteString -> Either String BSDiffPatch
parseBSDiff input
  | ByteString.length input < 32 = Left "BSDiff: input too short"
  | ByteString.take 8 input /= "BSDIFF40" = Left "not a BSDiff file (bad magic)"
  | rawControlSize < 0 || rawDiffSize < 0 || rawTargetSize < 0 = Left "BSDiff: invalid header (negative size)"
  | otherwise = do
      controlData  <- safeDecompressBZip "control" controlCompressed
      diffData  <- safeDecompressBZip "diff" diffCompressed
      extraData <- safeDecompressBZip "extra" extraCompressed
      let controls = parseControls controlData
          rawExtraSize = fromIntegral (ByteString.length input) - 32 - rawControlSize - rawDiffSize
      Right (BSDiffPatch (FileSize rawControlSize) (FileSize rawDiffSize) (FileSize rawExtraSize) (FileSize rawTargetSize) controls diffData extraData)
  where
    rawControlSize = getSignMagnitude64 8 input
    rawDiffSize = getSignMagnitude64 16 input
    rawTargetSize  = getSignMagnitude64 24 input
    controlOffset  = 32
    diffOffset  = 32 + fromIntegral rawControlSize
    extraOffset = diffOffset + fromIntegral rawDiffSize
    controlCompressed  = ByteString.take (fromIntegral rawControlSize) (ByteString.drop controlOffset input)
    diffCompressed  = ByteString.take (fromIntegral rawDiffSize) (ByteString.drop diffOffset input)
    extraCompressed = ByteString.drop extraOffset input

parseControls :: ByteString -> [BSDiffControl]
parseControls input
  | ByteString.length input < 24 = []
  | otherwise =
      BSDiffControl (getSignMagnitude64 0 input) (getSignMagnitude64 8 input) (Delta (getSignMagnitude64 16 input))
        : parseControls (ByteString.drop 24 input)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyBSDiff :: BSDiffPatch -> ByteString -> Either String ByteString
applyBSDiff patch _source
  | unFileSize (bsdiffTargetSize patch) == 0 = Right ByteString.empty
  | unFileSize (bsdiffTargetSize patch) < 0  = Left "BSDiff: negative target size"
applyBSDiff patch source = Right $ unsafeCreate outputSize $ \targetPointer ->
  applyLoop targetPointer 0 0 0 0 (bsdiffControls patch)
  where
    outputSize = fromIntegral (unFileSize (bsdiffTargetSize patch))
    sourceLength  = ByteString.length source
    diffBytes  = bsdiffDiffData patch
    extraBytes = bsdiffExtraData patch
    diffLength = ByteString.length diffBytes
    extraLength = ByteString.length extraBytes

    applyLoop :: Ptr Word8 -> Int -> Int -> Int -> Int -> [BSDiffControl] -> IO ()
    applyLoop _targetPointer _diffOffset _extraOffset _originalPosition _outputPosition [] = pure ()
    applyLoop targetPointer diffOffset extraOffset originalPosition outputPosition (control:rest) = do
      -- Clamp add/copy lengths to remaining output buffer space
      let addLength = max 0 $ min (fromIntegral (controlAdd control)) (outputSize - outputPosition)
          copyLength  = max 0 $ min (fromIntegral (controlCopy control)) (outputSize - outputPosition - addLength)
          seekOffset     = fromIntegral (unDelta (controlSeek control))
      -- Add: target[outputPosition+i] = source[originalPosition+i] + diff[diffOffset+i]
      mapM_ (\index -> do
        let sourceByte = if originalPosition + index >= 0 && originalPosition + index < sourceLength
                then ByteString.index source (originalPosition + index) else 0
            diffByte = if diffOffset + index >= 0 && diffOffset + index < diffLength
                then ByteString.index diffBytes (diffOffset + index) else 0
        pokeByteOff targetPointer (outputPosition + index) (sourceByte + diffByte :: Word8)) [0..addLength-1]
      -- Copy: target[outputPosition+addLength..] = extra[extraOffset..]
      let safeCopyLength = if extraOffset >= 0 && extraOffset < extraLength
                      then min copyLength (extraLength - extraOffset)
                      else 0
      copyByteStringRange targetPointer (outputPosition + addLength) extraBytes extraOffset safeCopyLength
      applyLoop targetPointer (diffOffset + addLength) (extraOffset + copyLength)
        (originalPosition + addLength + seekOffset) (outputPosition + addLength + copyLength) rest

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

bsdiffMeta :: BSDiffPatch -> [(String, String)]
bsdiffMeta patch =
  [ ("new size", show (unFileSize (bsdiffTargetSize patch)))
  , ("ctrl block", show (unFileSize (bsdiffControlSize patch)) ++ " bytes (compressed)")
  , ("diff block", show (unFileSize (bsdiffDiffSize patch)) ++ " bytes (compressed)")
  , ("extra block", show (unFileSize (bsdiffExtraSize patch)) ++ " bytes (compressed)")
  ]

bsdiffInfo :: BSDiffPatch -> String
bsdiffInfo patch = unlines $ filter (not . null) $
  [ "format:      BSDiff / BDF (BSDIFF40)" ]
  ++ map renderField (bsdiffMeta patch)
  ++ [ controlString ]
  where
    controlString
      | null (bsdiffControls patch) = ""
      | otherwise = "controls:    " ++ show (length (bsdiffControls patch)) ++ " tuples"
