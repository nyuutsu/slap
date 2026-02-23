{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.GDIFF
  ( GDiffPatch(..)
  , GDiffCmd(..)
  , parseGDIFF
  , applyGDIFF
  , createGDIFF
  , gdiffMeta
  , gdiffInfo
  ) where

-- Canonical reference: W3C NOTE-GDIFF-19970901

import Patch.Binary (copyBSRange, diffHunks, putWord16BE, putWord32BE, putInt64BE)
import Patch.Get (runGet, getByte, getBytes, word16BE, word32BE, int64BE)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
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
  | BS.length bs < 5 = Left "GDIFF: input too short"
  | BS.take 4 bs /= "\xd1\xff\xd1\xff" = Left "not a GDIFF file (bad magic)"
  | BS.index bs 4 /= 4 = Left ("GDIFF: unsupported version: " ++ show (BS.index bs 4))
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

        _ -> fail "impossible GDIFF opcode"  -- 0-255 covered above; GHC can't prove guard exhaustiveness

cmdOutSize :: GDiffCmd -> Int64
cmdOutSize (GDiffData d)    = fromIntegral (BS.length d)
cmdOutSize (GDiffCopy _ len) = len

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyGDIFF :: GDiffPatch -> ByteString -> Either String ByteString
applyGDIFF patch source
  | totalSize == 0 = Right BS.empty
  | otherwise = Right $ unsafeCreate (fromIntegral totalSize) $ \ptr ->
      go ptr 0 (gdiffCmds patch)
  where
    totalSize = sum (map cmdOutSize (gdiffCmds patch))

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

-- | GDIFF carries no header metadata; this returns an empty list.
gdiffMeta :: GDiffPatch -> [(String, String)]
gdiffMeta _ = []

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
    totalOut = sum (map cmdOutSize cmds)

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- Unchanged regions become COPY commands; changed regions become DATA commands.
createGDIFF :: ByteString -> ByteString -> ByteString
createGDIFF old new = BL.toStrict $ toLazyByteString $
    byteString "\xd1\xff\xd1\xff"   -- magic
    <> word8 4                       -- version
    <> buildCmds 0 (diffHunks old new)
    <> word8 0                       -- EOF command
  where
    minLen = min (BS.length old) (BS.length new)
    buildCmds pos [] =
      -- trailing unchanged region
      if pos < minLen then encodeCopy (fromIntegral pos) (fromIntegral (minLen - pos))
      else mempty
    buildCmds pos ((off, dat) : rest) =
      let gap = off - pos
          copyPart = if gap > 0 then encodeCopy (fromIntegral pos) (fromIntegral gap) else mempty
          dataPart = encodeData dat
      in copyPart <> dataPart <> buildCmds (off + BS.length dat) rest

-- | Encode a DATA command, splitting into chunks if > 2^31.
encodeData :: ByteString -> Builder
encodeData dat
  | BS.null dat = mempty
  | len <= 246  = word8 (fromIntegral len) <> byteString dat
  | len <= 0xFFFF = word8 247 <> putWord16BE len <> byteString dat
  | otherwise     = word8 248 <> putWord32BE (fromIntegral len) <> byteString dat
  where len = BS.length dat

-- | Encode a COPY command with optimal opcode selection.
encodeCopy :: Int64 -> Int64 -> Builder
encodeCopy off len
  -- COPY ushort,ubyte (249)
  | off <= 0xFFFF && len <= 0xFF =
      word8 249 <> putWord16BE (fromIntegral off) <> word8 (fromIntegral len)
  -- COPY ushort,ushort (250)
  | off <= 0xFFFF && len <= 0xFFFF =
      word8 250 <> putWord16BE (fromIntegral off) <> putWord16BE (fromIntegral len)
  -- COPY ushort,int (251)
  | off <= 0xFFFF =
      word8 251 <> putWord16BE (fromIntegral off) <> putWord32BE (fromIntegral len)
  -- COPY int,ubyte (252)
  | off <= 0xFFFFFFFF && len <= 0xFF =
      word8 252 <> putWord32BE (fromIntegral off) <> word8 (fromIntegral len)
  -- COPY int,ushort (253)
  | off <= 0xFFFFFFFF && len <= 0xFFFF =
      word8 253 <> putWord32BE (fromIntegral off) <> putWord16BE (fromIntegral len)
  -- COPY int,int (254)
  | off <= 0xFFFFFFFF =
      word8 254 <> putWord32BE (fromIntegral off) <> putWord32BE (fromIntegral len)
  -- COPY long,int (255)
  | otherwise =
      word8 255 <> putInt64BE off <> putWord32BE (fromIntegral len)

