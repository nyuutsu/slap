{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.GDIFF
  ( GDiffPatch(..)
  , GDiffCmd(..)
  , parseGDIFF
  , applyGDIFF
  , gdiffInfo
  ) where

import Patch.Binary (getWord16BE, getWord32BE, getInt64BE, copyBSRange)

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
  | otherwise = parseCmds 5 []
  where
    parseCmds pos acc
      | pos >= BS.length bs = Left "GDIFF: unexpected end of file (no EOF command)"
      | otherwise =
          let cmd = BS.index bs pos
          in case cmd of
            0 -> Right (GDiffPatch (reverse acc))

            -- DATA: inline, opcode IS the length (1-246 bytes)
            _ | cmd <= 246 ->
                let len = fromIntegral cmd
                    dat = BS.take len (BS.drop (pos + 1) bs)
                in parseCmds (pos + 1 + len) (GDiffData dat : acc)

            -- DATA with ushort length
            247 ->
                let len = fromIntegral (getWord16BE (pos + 1) bs)
                    dat = BS.take len (BS.drop (pos + 3) bs)
                in parseCmds (pos + 3 + len) (GDiffData dat : acc)

            -- DATA with int length
            248 ->
                let len = fromIntegral (getWord32BE (pos + 1) bs) :: Int
                    dat = BS.take len (BS.drop (pos + 5) bs)
                in parseCmds (pos + 5 + len) (GDiffData dat : acc)

            -- COPY ushort offset, ubyte length
            249 ->
                let off = fromIntegral (getWord16BE (pos + 1) bs)
                    len = fromIntegral (BS.index bs (pos + 3))
                in parseCmds (pos + 4) (GDiffCopy off len : acc)

            -- COPY ushort offset, ushort length
            250 ->
                let off = fromIntegral (getWord16BE (pos + 1) bs)
                    len = fromIntegral (getWord16BE (pos + 3) bs)
                in parseCmds (pos + 5) (GDiffCopy off len : acc)

            -- COPY ushort offset, int length
            251 ->
                let off = fromIntegral (getWord16BE (pos + 1) bs)
                    len = fromIntegral (getWord32BE (pos + 3) bs)
                in parseCmds (pos + 7) (GDiffCopy off len : acc)

            -- COPY int offset, ubyte length
            252 ->
                let off = fromIntegral (getWord32BE (pos + 1) bs)
                    len = fromIntegral (BS.index bs (pos + 5))
                in parseCmds (pos + 6) (GDiffCopy off len : acc)

            -- COPY int offset, ushort length
            253 ->
                let off = fromIntegral (getWord32BE (pos + 1) bs)
                    len = fromIntegral (getWord16BE (pos + 5) bs)
                in parseCmds (pos + 7) (GDiffCopy off len : acc)

            -- COPY int offset, int length
            254 ->
                let off = fromIntegral (getWord32BE (pos + 1) bs)
                    len = fromIntegral (getWord32BE (pos + 5) bs)
                in parseCmds (pos + 9) (GDiffCopy off len : acc)

            -- COPY long offset, int length
            255 ->
                let off = getInt64BE (pos + 1) bs
                    len = fromIntegral (getWord32BE (pos + 9) bs)
                in parseCmds (pos + 13) (GDiffCopy off len : acc)

            _ -> Left ("GDIFF: unknown command: " ++ show cmd)

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
