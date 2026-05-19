{-# LANGUAGE DerivingStrategies        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE StrictData                 #-}

-- | Monadic byte parser used by every per-format @Parse.hs@. A
-- @ByteParser a@ has read-only access to an input 'ByteString',
-- threads a mutable cursor 'Position', and can fail with a structured
-- 'ByteParserError'. Internally it's the standard transformer stack
--
-- @
-- StateT Position (ReaderT ByteString (Either ByteParserError))
-- @
--
-- wrapped in a newtype so that 'MonadFail' (which the 'Either' base
-- does not provide) can be defined honestly. State is the outer
-- layer because 'get'\/'put' are the dominant operations across the
-- primitive set and benefit from not needing 'lift'.
--
-- This module replaces the older @Slap.Get@\/@Get@ pair. Existing
-- primitive names ('getByte', 'getBytes', 'word32LE', 'byuuVarint',
-- and friends) are kept — they're verb-prefixed and describe what
-- they do; renaming would touch many more lines for less aesthetic
-- gain. The type and its runner ('ByteParser', 'runByteParser')
-- carry the load-bearing rename.
module Slap.ByteParser
  ( ByteParser
  , runByteParser
    -- * Primitives
  , getByte
  , getBytes
  , getUntilByte
  , skip
  , getPosition
  , setPosition
  , lookAhead
  , getInput
  , atEnd
  , remaining
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
import Slap.Measure
  ( Position(..), Length(..), remainingFromPosition
  , RequestedLength(..), RemainingLength(..), ActualLength(..)
  )
import Slap.Status
  ( ByteParserError(..)
  , ByteParserOperation(..)
  )

import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Reader (ReaderT(..), ask)
import Control.Monad.Trans.State.Strict
  ( StateT(..), evalStateT, get, put )

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)

----------------------------------------------------------------------------
-- The ByteParser monad: a standard transformer stack
----------------------------------------------------------------------------

-- | The byte-parser monad. The wrapped stack is
-- @StateT Position (ReaderT ByteString (Either ByteParserError))@.
-- The newtype exists for the 'MonadFail' instance below — 'Either'
-- has no 'MonadFail' and we want @do@-notation desugaring to land
-- in 'ByteParserUnexpectedDoPatternFailure' rather than @error@.
-- No record selector is needed (the helpers below pattern-match on
-- the constructor and the runner uses 'unwrap' directly), so we
-- use the constructor form rather than record syntax.
newtype ByteParser a
  = ByteParser (StateT Position (ReaderT ByteString (Either ByteParserError)) a)
  deriving newtype (Functor, Applicative, Monad)

-- | @do@-notation's @fail@ desugars here when a refutable pattern
-- bind inside slap's parser code doesn't match. The arm names that
-- explicitly: reaching it means slap has a bug, not that the wire
-- was malformed. Real failure shapes go through the typed
-- 'ByteParserError' constructors directly via 'throwByteParserError'.
instance MonadFail ByteParser where
  fail message =
    throwByteParserError (ByteParserUnexpectedDoPatternFailure message)

-- | Run a parser against an input 'ByteString' starting at offset
-- zero. The final position is discarded — no consumer cares where
-- the parser ended up, only what it produced. 'evalStateT' is the
-- transformer equivalent of @fst <$> runStateT@.
runByteParser :: ByteParser a -> ByteString -> Either ByteParserError a
runByteParser (ByteParser parser) input =
  runReaderT (evalStateT parser (Position 0)) input

----------------------------------------------------------------------------
-- Internal helpers
----------------------------------------------------------------------------

-- | Read the input 'ByteString'. Reaches through the state layer to
-- the reader's 'ask'; bundled here so the primitives don't repeat
-- the @lift ask@ ceremony.
askInput :: ByteParser ByteString
askInput = ByteParser (lift ask)

-- | Raise a structured parse error. Reaches through both transformer
-- layers to the base 'Either' and emits @Left@; bundled here so the
-- primitives don't repeat the @lift (lift (Left _))@ ceremony.
throwByteParserError :: ByteParserError -> ByteParser a
throwByteParserError errorValue =
  ByteParser (lift (lift (Left errorValue)))

----------------------------------------------------------------------------
-- Primitives
----------------------------------------------------------------------------

getByte :: ByteParser Word8
getByte = do
  singleByte <- getBytes (Length 1)
  pure (ByteString.index singleByte 0)

getBytes :: Length -> ByteParser ByteString
getBytes requestedLength@(Length count)
  | count < 0 =
      throwByteParserError
        (ByteParserNegativeLengthRequested GetBytesOperation requestedLength)
  | otherwise = do
      input              <- askInput
      currentPosition    <- ByteParser get
      let inputLength       = ByteString.length input
          Position startAt  = currentPosition
      if startAt + count <= inputLength
        then do
          ByteParser (put (Position (startAt + count)))
          pure (ByteString.take count (ByteString.drop startAt input))
        else
          throwByteParserError
            (ByteParserUnderflow
                GetBytesOperation
                (RequestedLength requestedLength)
                (RemainingLength (Length (inputLength - startAt)))
                currentPosition)

-- | Scan the remaining input for the first occurrence of the given
-- byte. Return the prefix as a zero-copy 'ByteString' slice and
-- advance past the terminator. Fail with
-- 'ByteParserTerminatorNotFound' if the byte is not found before
-- end of input.
getUntilByte :: Word8 -> ByteParser ByteString
getUntilByte terminatorByte = do
  input            <- askInput
  currentPosition  <- ByteParser get
  let Position startAt   = currentPosition
      remainingBytes     = ByteString.drop startAt input
  case ByteString.elemIndex terminatorByte remainingBytes of
    Nothing ->
      throwByteParserError
        (ByteParserTerminatorNotFound terminatorByte currentPosition)
    Just terminatorIndex -> do
      ByteParser (put (Position (startAt + terminatorIndex + 1)))
      pure (ByteString.take terminatorIndex remainingBytes)

skip :: Length -> ByteParser ()
skip requestedLength@(Length count)
  | count < 0 =
      throwByteParserError
        (ByteParserNegativeLengthRequested SkipOperation requestedLength)
  | otherwise = do
      input            <- askInput
      currentPosition  <- ByteParser get
      let inputLength      = ByteString.length input
          Position startAt = currentPosition
      if startAt + count <= inputLength
        then ByteParser (put (Position (startAt + count)))
        else
          throwByteParserError
            (ByteParserUnderflow
                SkipOperation
                (RequestedLength requestedLength)
                (RemainingLength (Length (inputLength - startAt)))
                currentPosition)

getPosition :: ByteParser Position
getPosition = ByteParser get

setPosition :: Position -> ByteParser ()
setPosition targetPosition@(Position targetValue) = do
  input <- askInput
  let inputLength = ByteString.length input
  if targetValue >= 0 && targetValue <= inputLength
    then ByteParser (put targetPosition)
    else
      throwByteParserError
        (ByteParserPositionOutOfBounds
            targetPosition
            (ActualLength (Length inputLength)))

-- | Run the given sub-parser for its result, then restore the cursor
-- to where it was before the sub-parser ran. The parser's state is
-- unchanged from the caller's perspective; only the returned value
-- reflects the sub-parse. If the sub-parser fails, 'lookAhead' fails
-- with the same error — peeks are real runs, not symbolic ones.
--
-- Standard parser-combinator shape; matches the 'lookAhead' found in
-- attoparsec, megaparsec, parsec, binary, and cereal.
lookAhead :: ByteParser a -> ByteParser a
lookAhead parser = do
  savedPosition <- getPosition
  result        <- parser
  setPosition savedPosition
  pure result

getInput :: ByteParser ByteString
getInput = askInput

atEnd :: ByteParser Bool
atEnd = do
  input            <- askInput
  Position cursor  <- ByteParser get
  pure (cursor >= ByteString.length input)

remaining :: ByteParser Length
remaining = do
  input           <- askInput
  currentPosition <- ByteParser get
  pure (remainingFromPosition currentPosition input)

----------------------------------------------------------------------------
-- Fixed-width readers (lifted from Slap.Binary)
----------------------------------------------------------------------------

-- | Adapt a fixed-width pure reader (one that consumes a known number
-- of bytes at a given offset in the input) into a 'ByteParser'.
-- Underflow is surfaced as 'ByteParserUnderflow' tagged with
-- 'FixedWidthReadOperation'.
liftRead :: Length -> (Int -> ByteString -> a) -> ByteParser a
liftRead readWidth@(Length width) reader = do
  input            <- askInput
  currentPosition  <- ByteParser get
  let inputLength      = ByteString.length input
      Position startAt = currentPosition
  if startAt + width <= inputLength
    then do
      ByteParser (put (Position (startAt + width)))
      pure (reader startAt input)
    else
      throwByteParserError
        (ByteParserUnderflow
            FixedWidthReadOperation
            (RequestedLength readWidth)
            (RemainingLength (Length (inputLength - startAt)))
            currentPosition)

-- | Adapt a variable-length pure varint reader. Two distinct failure
-- modes are surfaced separately: starting the read at or past EOF is
-- an 'ByteParserUnderflow' tagged with 'VarintReadOperation' (the
-- request asked for at least one byte, none were available); a varint
-- that starts inside the buffer but whose continuation bytes run past
-- the end is 'ByteParserVarintOverranBuffer'.
liftReadVarint :: (Int -> ByteString -> Either String VarintResult)
               -> ByteParser Int64
liftReadVarint reader = do
  input            <- askInput
  currentPosition  <- ByteParser get
  let inputLength      = ByteString.length input
      Position startAt = currentPosition
  if startAt >= inputLength
    then
      throwByteParserError
        (ByteParserUnderflow
            VarintReadOperation
            (RequestedLength (Length 1))
            (RemainingLength (Length 0))
            currentPosition)
    else case reader startAt input of
      Left underlyingMessage ->
        throwByteParserError (ByteParserVarintInternalError underlyingMessage)
      Right (VarintResult result consumed) ->
        if startAt + consumed > inputLength
          then
            throwByteParserError
              (ByteParserVarintOverranBuffer currentPosition)
          else do
            ByteParser (put (Position (startAt + consumed)))
            pure result

word16LE :: ByteParser Word16
word16LE = liftRead (Length 2) getWord16LE

word32LE :: ByteParser Word32
word32LE = liftRead (Length 4) getWord32LE

int64LE :: ByteParser Int64
int64LE = liftRead (Length 8) getInt64LE

word16BE :: ByteParser Word16
word16BE = liftRead (Length 2) getWord16BE

word24BE :: ByteParser Word32
word24BE = liftRead (Length 3) getWord24BE

word32BE :: ByteParser Word32
word32BE = liftRead (Length 4) getWord32BE

int64BE :: ByteParser Int64
int64BE = liftRead (Length 8) getInt64BE

----------------------------------------------------------------------------
-- Variable-length readers
----------------------------------------------------------------------------

byuuVarint :: ByteParser Int64
byuuVarint = liftReadVarint getByuuVarint

vcdiffVarint :: ByteParser Int64
vcdiffVarint = liftReadVarint getVcdiffVarint

-- | EDSIO variable-length unsigned int (LEB128-like, used by xdelta1).
-- 7 bits per byte, LSB first, high bit = continuation. Decoded inline
-- because the byuu and VCDIFF varints have a single combined reader
-- in 'Slap.Binary' but EDSIO's continuation discipline is bespoke.
-- Bit-offsets past 63 saturate the accumulator's representable range
-- and surface as 'ByteParserVarintExceededWidth'.
edsioVarint :: ByteParser Int64
edsioVarint = decode 0 0
  where
    decode accumulated bitOffset
      | bitOffset >= 63 =
          throwByteParserError ByteParserVarintExceededWidth
      | otherwise = do
          byte <- getByte
          let payload     = fromIntegral (byte .&. 0x7F) :: Int64
              withPayload = accumulated .|. (payload `shiftL` bitOffset)
          if testBit byte 7
            then decode withPayload (bitOffset + 7)
            else pure withPayload
