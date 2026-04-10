{-# LANGUAGE StrictData #-}

module Slap.Get
  ( Get
  , runGet
    -- * Primitives
  , getByte
  , getBytes
  , getUntilByte
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

import Slap.Binary
  ( VarintResult(..)
  , getWord16LE, getWord32LE, getInt64LE
  , getWord16BE, getWord24BE, getWord32BE, getInt64BE
  , getByuuVarint, getVcdiffVarint
  )
import Slap.Measure (Position(..), Length(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)

----------------------------------------------------------------------------
-- The Get monad: position-threading over a ByteString
----------------------------------------------------------------------------

newtype Get a = Get (ByteString -> Position -> Either String (a, Position))

runGet :: Get a -> ByteString -> Either String a
runGet (Get parser) input = fst <$> parser input (Position 0)

instance Functor Get where
  fmap function (Get parser) = Get $ \input position -> case parser input position of
    Left errorMessage                    -> Left errorMessage
    Right (result, positionAfter)    -> Right (function result, positionAfter)

instance Applicative Get where
  pure result = Get $ \_ position -> Right (result, position)
  Get parseFunction <*> Get parseArgument = Get $ \input position -> case parseFunction input position of
    Left errorMessage                     -> Left errorMessage
    Right (parsedFunction, positionAfterFunction) -> case parseArgument input positionAfterFunction of
      Left errorMessage                   -> Left errorMessage
      Right (result, positionAfterArgument)     -> Right (parsedFunction result, positionAfterArgument)

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
getByte = do
  singleByte <- getBytes (Length 1)
  pure (ByteString.index singleByte 0)

getBytes :: Length -> Get ByteString
getBytes (Length count)
  | count < 0 = Get $ \_ _ -> Left ("getBytes: negative length " ++ show count)
  | otherwise  = Get $ \input (Position position) ->
      if position + count <= ByteString.length input
      then Right (ByteString.take count (ByteString.drop position input), Position (position + count))
      else Left ("getBytes: need " ++ show count ++ " bytes at offset " ++ show position ++ " but only " ++ show (ByteString.length input - position) ++ " available")

-- | Scan the remaining input for the first occurrence of the given
-- byte. Return the prefix as a zero-copy ByteString slice and advance
-- past the terminator. Fail if the byte is not found before end of
-- input.
getUntilByte :: Word8 -> Get ByteString
getUntilByte terminatorByte = Get $ \input (Position position) ->
  let remainingBytes = ByteString.drop position input
  in case ByteString.elemIndex terminatorByte remainingBytes of
    Nothing -> Left ("getUntilByte: terminator not found at offset " ++ show position)
    Just index ->
      Right (ByteString.take index remainingBytes, Position (position + index + 1))

skip :: Length -> Get ()
skip (Length count)
  | count < 0 = Get $ \_ _ -> Left ("skip: negative count " ++ show count)
  | otherwise  = Get $ \input (Position position) ->
      let newPosition = position + count
      in if newPosition <= ByteString.length input
         then Right ((), Position newPosition)
         else Left ("skip: offset " ++ show newPosition ++ " out of bounds")

getPosition :: Get Position
getPosition = Get $ \_ position -> Right (position, position)

setPosition :: Position -> Get ()
setPosition target@(Position targetValue) = Get $ \input _ ->
  if targetValue >= 0 && targetValue <= ByteString.length input
  then Right ((), target)
  else Left ("setPosition: " ++ show targetValue ++ " out of bounds")

getInput :: Get ByteString
getInput = Get $ \input position -> Right (input, position)

atEnd :: Get Bool
atEnd = Get $ \input (Position position) -> Right (position >= ByteString.length input, Position position)

remaining :: Get Length
remaining = Get $ \input (Position position) -> Right (Length (ByteString.length input - position), Position position)

failGet :: String -> Get a
failGet = fail

----------------------------------------------------------------------------
-- Fixed-width readers (lifted from Slap.Binary)
----------------------------------------------------------------------------

liftRead :: Length -> (Int -> ByteString -> a) -> Get a
liftRead (Length width) reader = Get $ \input (Position position) ->
  if position + width <= ByteString.length input
  then Right (reader position input, Position (position + width))
  else Left ("liftRead: need " ++ show width ++ " bytes at offset " ++ show position)

liftReadVarint :: (Int -> ByteString -> Either String VarintResult) -> Get Int64
liftReadVarint reader = Get $ \input (Position position) ->
  if position >= ByteString.length input
  then Left ("liftReadVarint: read past end at offset " ++ show position)
  else case reader position input of
    Left errorMessage -> Left errorMessage
    Right (VarintResult result consumed) ->
      if position + consumed > ByteString.length input
      then Left ("liftReadVarint: varint overran buffer at offset " ++ show position)
      else Right (result, Position (position + consumed))

word16LE :: Get Word16
word16LE = liftRead (Length 2) getWord16LE

word32LE :: Get Word32
word32LE = liftRead (Length 4) getWord32LE

int64LE :: Get Int64
int64LE = liftRead (Length 8) getInt64LE

word16BE :: Get Word16
word16BE = liftRead (Length 2) getWord16BE

word24BE :: Get Word32
word24BE = liftRead (Length 3) getWord24BE

word32BE :: Get Word32
word32BE = liftRead (Length 4) getWord32BE

int64BE :: Get Int64
int64BE = liftRead (Length 8) getInt64BE

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
      | bitOffset > 63 = fail "varint overflow (too many continuation bytes)"
      | otherwise = do
          byte <- getByte
          let payload = fromIntegral (byte .&. 0x7F) :: Int64
              withPayload = accumulated .|. (payload `shiftL` bitOffset)
          if testBit byte 7
            then decode withPayload (bitOffset + 7)
            else pure withPayload
