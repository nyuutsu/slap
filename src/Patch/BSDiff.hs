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
import qualified Data.ByteString as BS
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Patch.Binary (copyBSRange)
import Patch.Compress (bz2Decompress)
import Patch.Format (renderField)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (pokeByteOff)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data BSDiffPatch = BSDiffPatch
  { bsdCtrlSize  :: Int64       -- compressed control block size
  , bsdDiffSize  :: Int64       -- compressed diff block size
  , bsdExtraSize :: Int64       -- compressed extra block size
  , bsdNewSize   :: Int64       -- target file size
  , bsdControls  :: [BSDiffControl]
  , bsdDiffData  :: ByteString  -- decompressed diff stream
  , bsdExtraData :: ByteString  -- decompressed extra stream
  } deriving (Show)

data BSDiffControl = BSDiffControl
  { ctrlAdd  :: Int64   -- bytes to add from diff stream to source
  , ctrlCopy :: Int64   -- bytes to copy from extra stream
  , ctrlSeek :: Int64   -- signed seek offset in source
  } deriving (Show)

----------------------------------------------------------------------------
-- Signed LE64 (bsdiff sign-magnitude encoding)
----------------------------------------------------------------------------

-- | Read a signed 64-bit LE value in bsdiff format.
-- Bit 63 of byte 7 is the sign; lower 63 bits are the magnitude (LE).
getSignMagnitude64 :: Int -> ByteString -> Int64
getSignMagnitude64 off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Int64
      magnitude = b 0 .|. (b 1 `shiftL` 8) .|. (b 2 `shiftL` 16) .|. (b 3 `shiftL` 24)
                  .|. (b 4 `shiftL` 32) .|. (b 5 `shiftL` 40) .|. (b 6 `shiftL` 48)
                  .|. ((b 7 .&. 0x7F) `shiftL` 56)
  in if testBit (BS.index bs (off + 7)) 7
     then negate magnitude
     else magnitude

----------------------------------------------------------------------------
-- Safe decompression
----------------------------------------------------------------------------

safeDecompressBZip :: String -> ByteString -> Either String ByteString
safeDecompressBZip _     compressed | BS.null compressed = Right BS.empty
safeDecompressBZip label compressed = case bz2Decompress compressed of
  Left _  -> Left ("BSDiff: " ++ label ++ " decompression failed")
  Right d -> Right d

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseBSDiff :: ByteString -> Either String BSDiffPatch
parseBSDiff bs
  | BS.length bs < 32 = Left "BSDiff: input too short"
  | BS.take 8 bs /= "BSDIFF40" = Left "not a BSDiff file (bad magic)"
  | ctrlSz < 0 || diffSz < 0 || newSz < 0 = Left "BSDiff: invalid header (negative size)"
  | otherwise = do
      ctrlData  <- safeDecompressBZip "control" ctrlCompressed
      diffData  <- safeDecompressBZip "diff" diffCompressed
      extraData <- safeDecompressBZip "extra" extraCompressed
      let controls = parseControls ctrlData
          extraSz = fromIntegral (BS.length bs) - 32 - ctrlSz - diffSz
      Right (BSDiffPatch ctrlSz diffSz extraSz newSz controls diffData extraData)
  where
    ctrlSz = getSignMagnitude64 8 bs
    diffSz = getSignMagnitude64 16 bs
    newSz  = getSignMagnitude64 24 bs
    ctrlOff  = 32
    diffOff  = 32 + fromIntegral ctrlSz
    extraOff = diffOff + fromIntegral diffSz
    ctrlCompressed  = BS.take (fromIntegral ctrlSz) (BS.drop ctrlOff bs)
    diffCompressed  = BS.take (fromIntegral diffSz) (BS.drop diffOff bs)
    extraCompressed = BS.drop extraOff bs

parseControls :: ByteString -> [BSDiffControl]
parseControls bs
  | BS.length bs < 24 = []
  | otherwise =
      BSDiffControl (getSignMagnitude64 0 bs) (getSignMagnitude64 8 bs) (getSignMagnitude64 16 bs)
        : parseControls (BS.drop 24 bs)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyBSDiff :: BSDiffPatch -> ByteString -> Either String ByteString
applyBSDiff patch _source
  | bsdNewSize patch == 0 = Right BS.empty
  | bsdNewSize patch < 0  = Left "BSDiff: negative target size"
applyBSDiff patch source = Right $ unsafeCreate sz $ \ptr ->
  go ptr 0 0 0 0 (bsdControls patch)
  where
    sz      = fromIntegral (bsdNewSize patch)
    srcLen  = BS.length source
    diffBs  = bsdDiffData patch
    extraBs = bsdExtraData patch
    diffLen = BS.length diffBs
    extraLen = BS.length extraBs

    go :: Ptr Word8 -> Int -> Int -> Int -> Int -> [BSDiffControl] -> IO ()
    go _ptr _dOff _eOff _oPos _nPos [] = pure ()
    go ptr dOff eOff oPos nPos (ctrl:rest) = do
      -- Clamp add/copy lengths to remaining output buffer space
      let addLen = max 0 $ min (fromIntegral (ctrlAdd ctrl)) (sz - nPos)
          cpLen  = max 0 $ min (fromIntegral (ctrlCopy ctrl)) (sz - nPos - addLen)
          sk     = fromIntegral (ctrlSeek ctrl)
      -- Add: target[nPos+i] = source[oPos+i] + diff[dOff+i]
      mapM_ (\i -> do
        let s = if oPos + i >= 0 && oPos + i < srcLen
                then BS.index source (oPos + i) else 0
            d = if dOff + i >= 0 && dOff + i < diffLen
                then BS.index diffBs (dOff + i) else 0
        pokeByteOff ptr (nPos + i) (s + d :: Word8)) [0..addLen-1]
      -- Copy: target[nPos+addLen..] = extra[eOff..]
      let safeCpLen = if eOff >= 0 && eOff < extraLen
                      then min cpLen (extraLen - eOff)
                      else 0
      copyBSRange ptr (nPos + addLen) extraBs eOff safeCpLen
      go ptr (dOff + addLen) (eOff + cpLen)
        (oPos + addLen + sk) (nPos + addLen + cpLen) rest

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

bsdiffMeta :: BSDiffPatch -> [(String, String)]
bsdiffMeta p =
  [ ("new size", show (bsdNewSize p))
  , ("ctrl block", show (bsdCtrlSize p) ++ " bytes (compressed)")
  , ("diff block", show (bsdDiffSize p) ++ " bytes (compressed)")
  , ("extra block", show (bsdExtraSize p) ++ " bytes (compressed)")
  ]

bsdiffInfo :: BSDiffPatch -> String
bsdiffInfo p = unlines $ filter (not . null) $
  [ "format:      BSDiff / BDF (BSDIFF40)" ]
  ++ map renderField (bsdiffMeta p)
  ++ [ ctrlStr ]
  where
    ctrlStr
      | null (bsdControls p) = ""
      | otherwise = "controls:    " ++ show (length (bsdControls p)) ++ " tuples"
