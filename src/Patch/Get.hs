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
  , liftReadVarint
  ) where

import Patch.Binary
  ( getWord16LE, getWord32LE, getInt64LE
  , getWord16BE, getWord24BE, getWord32BE, getInt64BE
  , getByuuVarint, getVcdiffVarint
  )

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)

----------------------------------------------------------------------------
-- The Get monad: position-threading over a ByteString
----------------------------------------------------------------------------

newtype Get a = Get (ByteString -> Int -> Either String (a, Int))

runGet :: Get a -> ByteString -> Either String a
runGet (Get parser) input = fst <$> parser input 0

instance Functor Get where
  fmap function (Get parser) = Get $ \input position -> case parser input position of
    Left errorMessage                    -> Left errorMessage
    Right (result, positionAfter)    -> Right (function result, positionAfter)

instance Applicative Get where
  pure result = Get $ \_ position -> Right (result, position)
  Get parseFunction <*> Get parseArgument = Get $ \input position -> case parseFunction input position of
    Left errorMessage                     -> Left errorMessage
    Right (f, positionAfterFunction)      -> case parseArgument input positionAfterFunction of
      Left errorMessage                   -> Left errorMessage
      Right (result, positionAfterArgument)     -> Right (f result, positionAfterArgument)

instance Monad Get where
  Get parseArgument >>= continuation = Get $ \input position -> case parseArgument input position of
    Left errorMessage                     -> Left errorMessage
    Right (result, positionAfterFirst)     -> let Get next = continuation result in next input positionAfterFirst

instance MonadFail Get where
  fail message = Get $ \_ _ -> Left message

----------------------------------------------------------------------------
-- Primitives
----------------------------------------------------------------------------

getByte :: Get Word8
getByte = Get $ \input position ->
  if position < ByteString.length input
  then Right (ByteString.index input position, position + 1)
  else Left ("getByte: offset " ++ show position ++ " out of bounds (length " ++ show (ByteString.length input) ++ ")")

getBytes :: Int -> Get ByteString
getBytes count
  | count < 0 = Get $ \_ _ -> Left ("getBytes: negative length " ++ show count)
  | otherwise  = Get $ \input position ->
      if position + count <= ByteString.length input
      then Right (ByteString.take count (ByteString.drop position input), position + count)
      else Left ("getBytes: need " ++ show count ++ " bytes at offset " ++ show position ++ " but only " ++ show (ByteString.length input - position) ++ " available")

skip :: Int -> Get ()
skip count
  | count < 0 = Get $ \_ _ -> Left ("skip: negative count " ++ show count)
  | otherwise  = Get $ \input position ->
      let newPosition = position + count
      in if newPosition <= ByteString.length input
         then Right ((), newPosition)
         else Left ("skip: offset " ++ show newPosition ++ " out of bounds")

getPosition :: Get Int
getPosition = Get $ \_ position -> Right (position, position)

setPosition :: Int -> Get ()
setPosition target = Get $ \input _ ->
  if target >= 0 && target <= ByteString.length input
  then Right ((), target)
  else Left ("setPosition: " ++ show target ++ " out of bounds")

getInput :: Get ByteString
getInput = Get $ \input position -> Right (input, position)

atEnd :: Get Bool
atEnd = Get $ \input position -> Right (position >= ByteString.length input, position)

remaining :: Get Int
remaining = Get $ \input position -> Right (ByteString.length input - position, position)

failGet :: String -> Get a
failGet = fail

----------------------------------------------------------------------------
-- Fixed-width readers (lifted from Patch.Binary)
----------------------------------------------------------------------------

liftRead :: Int -> (Int -> ByteString -> a) -> Get a
liftRead width reader = Get $ \input position ->
  if position + width <= ByteString.length input
  then Right (reader position input, position + width)
  else Left ("liftRead: need " ++ show width ++ " bytes at offset " ++ show position)

liftReadVarint :: (Int -> ByteString -> (a, Int)) -> Get a
liftReadVarint reader = Get $ \input position ->
  if position >= ByteString.length input
  then Left ("liftReadVarint: read past end at offset " ++ show position)
  else let (result, consumed) = reader position input
       in if position + consumed > ByteString.length input
          then Left ("liftReadVarint: varint overran buffer at offset " ++ show position)
          else Right (result, position + consumed)

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
byuuVarint = liftReadVarint getByuuVarint

vcdiffVarint :: Get Int64
vcdiffVarint = liftReadVarint getVcdiffVarint

-- | EDSIO variable-length unsigned int (LEB128-like, used by xdelta1).
-- 7 bits per byte, LSB first, high bit = continuation.
edsioVarint :: Get Int64
edsioVarint = decode 0 0
  where
    decode accumulated bitOffset
      | bitOffset > 63 = fail "edsioVarint: too many continuation bytes"
      | otherwise = do
          byte <- getByte
          let payload = fromIntegral (byte .&. 0x7F) :: Int64
              withPayload = accumulated .|. (payload `shiftL` bitOffset)
          if testBit byte 7
            then decode withPayload (bitOffset + 7)
            else pure withPayload
