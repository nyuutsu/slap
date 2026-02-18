{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.BSDiff
  ( BSDiffPatch(..)
  , BSDiffControl(..)
  , parseBSDiff
  , applyBSDiff
  , tryExternalBspatch
  , bsdiffInfo
  ) where

import qualified Codec.Compression.BZip as BZip
import qualified Data.ByteString.Lazy as BL
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (pokeByteOff)
import System.Directory (findExecutable)
import System.Exit (ExitCode(..))
import System.Process (readProcessWithExitCode)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data BSDiffPatch = BSDiffPatch
  { bsdCtrlSize  :: Int64       -- compressed control block size
  , bsdDiffSize  :: Int64       -- compressed diff block size
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
getOffT :: Int -> ByteString -> Int64
getOffT off bs =
  let b i = fromIntegral (BS.index bs (off + i)) :: Int64
      magnitude = b 0 .|. (b 1 `shiftL` 8) .|. (b 2 `shiftL` 16) .|. (b 3 `shiftL` 24)
                  .|. (b 4 `shiftL` 32) .|. (b 5 `shiftL` 40) .|. (b 6 `shiftL` 48)
                  .|. ((b 7 .&. 0x7F) `shiftL` 56)
  in if testBit (BS.index bs (off + 7)) 7
     then negate magnitude
     else magnitude

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseBSDiff :: ByteString -> Either String BSDiffPatch
parseBSDiff bs
  | BS.length bs < 32 = Left "too short for bsdiff header"
  | BS.take 8 bs /= "BSDIFF40" = Left "not a bsdiff file (bad magic)"
  | ctrlSz < 0 || diffSz < 0 || newSz < 0 = Left "negative size in bsdiff header"
  | otherwise =
      let ctrlOff  = 32
          diffOff  = 32 + fromIntegral ctrlSz
          extraOff = diffOff + fromIntegral diffSz
          ctrlCompressed  = BS.take (fromIntegral ctrlSz) (BS.drop ctrlOff bs)
          diffCompressed  = BS.take (fromIntegral diffSz) (BS.drop diffOff bs)
          extraCompressed = BS.drop extraOff bs
          ctrlData  = BL.toStrict $ BZip.decompress $ BL.fromStrict ctrlCompressed
          diffData  = BL.toStrict $ BZip.decompress $ BL.fromStrict diffCompressed
          extraData = BL.toStrict $ BZip.decompress $ BL.fromStrict extraCompressed
          controls  = parseControls ctrlData
      in Right (BSDiffPatch ctrlSz diffSz newSz controls diffData extraData)
  where
    ctrlSz = getOffT 8 bs
    diffSz = getOffT 16 bs
    newSz  = getOffT 24 bs

parseControls :: ByteString -> [BSDiffControl]
parseControls bs
  | BS.length bs < 24 = []
  | otherwise =
      BSDiffControl (getOffT 0 bs) (getOffT 8 bs) (getOffT 16 bs)
        : parseControls (BS.drop 24 bs)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyBSDiff :: BSDiffPatch -> ByteString -> Either String ByteString
applyBSDiff patch _source
  | bsdNewSize patch == 0 = Right BS.empty
applyBSDiff patch source = Right $ unsafeCreate sz $ \ptr ->
  go ptr 0 0 0 0 (bsdControls patch)
  where
    sz     = fromIntegral (bsdNewSize patch)
    srcLen = BS.length source
    diffBs = bsdDiffData patch
    extraBs = bsdExtraData patch

    go :: Ptr Word8 -> Int -> Int -> Int -> Int -> [BSDiffControl] -> IO ()
    go _ptr _dOff _eOff _oPos _nPos [] = pure ()
    go ptr dOff eOff oPos nPos (ctrl:rest) = do
      let addLen = fromIntegral (ctrlAdd ctrl)
          cpLen  = fromIntegral (ctrlCopy ctrl)
          sk     = fromIntegral (ctrlSeek ctrl)
      -- Add: target[nPos+i] = source[oPos+i] + diff[dOff+i]
      mapM_ (\i -> do
        let s = if oPos + i >= 0 && oPos + i < srcLen
                then BS.index source (oPos + i) else 0
            d = BS.index diffBs (dOff + i)
        pokeByteOff ptr (nPos + i) (s + d :: Word8)) [0..addLen-1]
      -- Copy: target[nPos+addLen+i] = extra[eOff+i]
      mapM_ (\i ->
        pokeByteOff ptr (nPos + addLen + i)
          (BS.index extraBs (eOff + i) :: Word8)) [0..cpLen-1]
      go ptr (dOff + addLen) (eOff + cpLen)
        (oPos + addLen + sk) (nPos + addLen + cpLen) rest

----------------------------------------------------------------------------
-- External fallback
----------------------------------------------------------------------------

-- | Try to apply a bsdiff patch using external bspatch command.
tryExternalBspatch :: FilePath -> FilePath -> FilePath -> IO (Either String ())
tryExternalBspatch patchPath sourcePath outputPath = do
  mBspatch <- findExecutable "bspatch"
  case mBspatch of
    Nothing -> pure (Left "bspatch not found on PATH")
    Just _ -> do
      (ec, _out, err) <- readProcessWithExitCode "bspatch"
        [sourcePath, outputPath, patchPath] ""
      pure $ case ec of
        ExitSuccess   -> Right ()
        ExitFailure n -> Left ("bspatch exited with code " ++ show n ++ ": " ++ err)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

bsdiffInfo :: BSDiffPatch -> String
bsdiffInfo p = unlines $ filter (not . null)
  [ "format:      BSDiff / BDF (BSDIFF40)"
  , "new size:    " ++ show (bsdNewSize p)
  , "ctrl block:  " ++ show (bsdCtrlSize p) ++ " bytes (compressed)"
  , "diff block:  " ++ show (bsdDiffSize p) ++ " bytes (compressed)"
  , ctrlStr
  ]
  where
    ctrlStr
      | null (bsdControls p) = ""
      | otherwise = "controls:    " ++ show (length (bsdControls p)) ++ " tuples"
