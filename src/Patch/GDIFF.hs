{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.GDIFF
  ( GDiffPatch(..)
  , GDiffCmd(..)
  , parseGDIFF
  , applyGDIFF
  , gdiffInfo
  ) where

import Patch.Binary (copyBSRange)
import Patch.Get (runGet, getByte, getBytes, word16BE, word32BE, int64BE, failGet)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Internal (unsafeCreate)
import Data.Int (Int64)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data GDiffCmd
  = GDiffData ByteString       -- literal data to append
  | GDiffCopy Int64 Int64      -- offset into source, length
  deriving (Show)

data GDiffPatch = GDiffPatch
  { gdiffCmds :: [GDiffCmd]
  } deriving (Show)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseGDIFF :: ByteString -> Either String GDiffPatch
parseGDIFF bs
  | BS.length bs < 5 = Left "too short for GDIFF header"
  | BS.take 4 bs /= "\xd1\xff\xd1\xff" = Left "not a GDIFF file (bad magic)"
  | BS.index bs 4 /= 4 = Left ("unsupported GDIFF version: " ++ show (BS.index bs 4))
  | otherwise = runGet (do { _ <- getBytes 5; parseCmds [] }) bs
  where
    parseCmds acc = do
      cmd <- getByte
      case cmd of
        0 -> pure (GDiffPatch (reverse acc))

        -- DATA: opcode IS the length (1-246 bytes)
        _ | cmd <= 246 -> do
              dat <- getBytes (fromIntegral cmd)
              parseCmds (GDiffData dat : acc)

        -- DATA with ushort length
        247 -> do len <- fromIntegral <$> word16BE
                  dat <- getBytes len
                  parseCmds (GDiffData dat : acc)

        -- DATA with int length
        248 -> do len <- fromIntegral <$> word32BE
                  dat <- getBytes len
                  parseCmds (GDiffData dat : acc)

        -- COPY ushort offset, ubyte length
        249 -> do off <- fromIntegral <$> word16BE
                  len <- fromIntegral <$> getByte
                  parseCmds (GDiffCopy off len : acc)

        -- COPY ushort offset, ushort length
        250 -> do off <- fromIntegral <$> word16BE
                  len <- fromIntegral <$> word16BE
                  parseCmds (GDiffCopy off len : acc)

        -- COPY ushort offset, int length
        251 -> do off <- fromIntegral <$> word16BE
                  len <- fromIntegral <$> word32BE
                  parseCmds (GDiffCopy off len : acc)

        -- COPY int offset, ubyte length
        252 -> do off <- fromIntegral <$> word32BE
                  len <- fromIntegral <$> getByte
                  parseCmds (GDiffCopy off len : acc)

        -- COPY int offset, ushort length
        253 -> do off <- fromIntegral <$> word32BE
                  len <- fromIntegral <$> word16BE
                  parseCmds (GDiffCopy off len : acc)

        -- COPY int offset, int length
        254 -> do off <- fromIntegral <$> word32BE
                  len <- fromIntegral <$> word32BE
                  parseCmds (GDiffCopy off len : acc)

        -- COPY long offset, int length
        255 -> do off <- int64BE
                  len <- fromIntegral <$> word32BE
                  parseCmds (GDiffCopy off len : acc)

        _ -> failGet ("GDIFF: unknown command: " ++ show cmd)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyGDIFF :: GDiffPatch -> ByteString -> Either String ByteString
applyGDIFF patch source
  | totalSize == 0 = Right BS.empty
  | otherwise = Right $ unsafeCreate (fromIntegral totalSize) $ \ptr ->
      go ptr 0 (gdiffCmds patch)
  where
    totalSize = sum [cmdOutSize c | c <- gdiffCmds patch] :: Int64

    cmdOutSize :: GDiffCmd -> Int64
    cmdOutSize (GDiffData d) = fromIntegral (BS.length d)
    cmdOutSize (GDiffCopy _ len) = len

    go :: Ptr Word8 -> Int -> [GDiffCmd] -> IO ()
    go _ptr _pos [] = pure ()
    go ptr pos (cmd:rest) = case cmd of
      GDiffData dat -> do
        let len = BS.length dat
        copyBSRange ptr pos dat 0 len
        go ptr (pos + len) rest
      GDiffCopy off len -> do
        let srcOff = fromIntegral off
            copyLen = fromIntegral len :: Int
        copyBSRange ptr pos source srcOff copyLen
        go ptr (pos + copyLen) rest

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

gdiffInfo :: GDiffPatch -> String
gdiffInfo p = unlines $ filter (not . null)
  [ "format:      GDIFF (W3C)"
  , "commands:    " ++ show nCmds
  , "data cmds:   " ++ show nData ++ " (" ++ show dataBytes ++ " bytes)"
  , "copy cmds:   " ++ show nCopy
  , "output size: " ++ show totalOut
  ]
  where
    cmds = gdiffCmds p
    nCmds = length cmds
    nData = length [() | GDiffData _ <- cmds]
    nCopy = length [() | GDiffCopy _ _ <- cmds]
    dataBytes = sum [BS.length d | GDiffData d <- cmds]
    totalOut = sum $ map cmdOutSize cmds
    cmdOutSize (GDiffData d) = fromIntegral (BS.length d) :: Int64
    cmdOutSize (GDiffCopy _ l) = l
