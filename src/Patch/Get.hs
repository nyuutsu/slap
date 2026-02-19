{-# LANGUAGE StrictData #-}

module Patch.Get
  ( Get
  , runGet
    -- * Primitives
  , getByte
  , getBytes
  , skip
  , getPosition
  , setPosition
  , getInput
  , atEnd
  , remaining
  , failGet
    -- * Fixed-width readers
  , word16LE
  , word32LE
  , int64LE
  , word16BE
  , word24BE
  , word32BE
  , int64BE
    -- * Variable-length readers
  , byuuVarint
  , vcdiffVarint
  , edsioVarint
    -- * Lifting raw Binary readers
  , liftRead
  , liftReadV
  ) where

import Patch.Binary
  ( getWord16LE, getWord32LE, getInt64LE
  , getWord16BE, getWord24BE, getWord32BE, getInt64BE
  , getByuuVarint, getVcdiffVarint
  )

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)

----------------------------------------------------------------------------
-- The Get monad: position-threading over a ByteString
----------------------------------------------------------------------------

newtype Get a = Get (ByteString -> Int -> Either String (a, Int))

runGet :: Get a -> ByteString -> Either String a
runGet (Get f) bs = fst <$> f bs 0

instance Functor Get where
  fmap g (Get f) = Get $ \bs pos -> case f bs pos of
    Left err      -> Left err
    Right (a, p') -> Right (g a, p')

instance Applicative Get where
  pure a = Get $ \_ pos -> Right (a, pos)
  Get ff <*> Get fa = Get $ \bs pos -> case ff bs pos of
    Left err      -> Left err
    Right (f, p1) -> case fa bs p1 of
      Left err      -> Left err
      Right (a, p2) -> Right (f a, p2)

instance Monad Get where
  Get fa >>= k = Get $ \bs pos -> case fa bs pos of
    Left err      -> Left err
    Right (a, p1) -> let Get fb = k a in fb bs p1

instance MonadFail Get where
  fail msg = Get $ \_ _ -> Left msg

----------------------------------------------------------------------------
-- Primitives
----------------------------------------------------------------------------

getByte :: Get Word8
getByte = Get $ \bs pos ->
  if pos < BS.length bs
  then Right (BS.index bs pos, pos + 1)
  else Left ("getByte: offset " ++ show pos ++ " out of bounds (length " ++ show (BS.length bs) ++ ")")

getBytes :: Int -> Get ByteString
getBytes n = Get $ \bs pos ->
  if pos + n <= BS.length bs
  then Right (BS.take n (BS.drop pos bs), pos + n)
  else Left ("getBytes: need " ++ show n ++ " bytes at offset " ++ show pos ++ " but only " ++ show (BS.length bs - pos) ++ " available")

skip :: Int -> Get ()
skip n = Get $ \bs pos ->
  let pos' = pos + n
  in if pos' <= BS.length bs
     then Right ((), pos')
     else Left ("skip: offset " ++ show pos' ++ " out of bounds")

getPosition :: Get Int
getPosition = Get $ \_ pos -> Right (pos, pos)

setPosition :: Int -> Get ()
setPosition pos = Get $ \bs _ ->
  if pos >= 0 && pos <= BS.length bs
  then Right ((), pos)
  else Left ("setPosition: " ++ show pos ++ " out of bounds")

getInput :: Get ByteString
getInput = Get $ \bs pos -> Right (bs, pos)

atEnd :: Get Bool
atEnd = Get $ \bs pos -> Right (pos >= BS.length bs, pos)

remaining :: Get Int
remaining = Get $ \bs pos -> Right (BS.length bs - pos, pos)

failGet :: String -> Get a
failGet = fail

----------------------------------------------------------------------------
-- Fixed-width readers (lifted from Patch.Binary)
----------------------------------------------------------------------------

liftRead :: Int -> (Int -> ByteString -> a) -> Get a
liftRead width f = Get $ \bs pos ->
  if pos + width <= BS.length bs
  then Right (f pos bs, pos + width)
  else Left ("liftRead: need " ++ show width ++ " bytes at offset " ++ show pos)

liftReadV :: (Int -> ByteString -> (a, Int)) -> Get a
liftReadV f = Get $ \bs pos ->
  if pos >= BS.length bs
  then Left ("liftReadV: read past end at offset " ++ show pos)
  else let (val, consumed) = f pos bs
       in if pos + consumed > BS.length bs
          then Left ("liftReadV: varint overran buffer at offset " ++ show pos)
          else Right (val, pos + consumed)

word16LE :: Get Word16
word16LE = liftRead 2 getWord16LE

word32LE :: Get Word32
word32LE = liftRead 4 getWord32LE

int64LE :: Get Int64
int64LE = liftRead 8 getInt64LE

word16BE :: Get Word16
word16BE = liftRead 2 getWord16BE

word24BE :: Get Word32
word24BE = liftRead 3 getWord24BE

word32BE :: Get Word32
word32BE = liftRead 4 getWord32BE

int64BE :: Get Int64
int64BE = liftRead 8 getInt64BE

----------------------------------------------------------------------------
-- Variable-length readers
----------------------------------------------------------------------------

byuuVarint :: Get Int64
byuuVarint = liftReadV getByuuVarint

vcdiffVarint :: Get Int64
vcdiffVarint = liftReadV getVcdiffVarint

-- | EDSIO variable-length unsigned int (LEB128-like, used by xdelta1).
-- 7 bits per byte, LSB first, high bit = continuation.
edsioVarint :: Get Int64
edsioVarint = go 0 0
  where
    go acc shift = do
      byte <- getByte
      let val = fromIntegral (byte .&. 0x7F) :: Int64
          acc' = acc .|. (val `shiftL` shift)
      if testBit byte 7
        then go acc' (shift + 7)
        else pure acc'
