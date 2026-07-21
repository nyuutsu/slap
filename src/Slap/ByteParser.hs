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
-- wrapped in a newtype so that 'MonadFail' (which the 'Either' base does not provide) can be defined at all.
-- State is the outer layer because 'get' and 'put' are the dominant operations across the primitive set and benefit from not needing 'lift'.
module Slap.ByteParser
  ( ByteParser
  , runByteParser
  , runFormatParser
  , flattenParse
  , throwByteParserError
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
    -- * Combinators
  , parseWhen
    -- * Fixed-width readers
  , word16LE
  , word32LE
  , int16LE
  , int32LE
  , int64LE
  , word16BE
  , word24BE
  , word32BE
  , int16BE
  , int32BE
  , int64BE
    -- * Variable-length readers
  , byuuVarint
  , vcdiffVarint
  , VcdiffVarintReading(..)
  , vcdiffVarintReportingCanonicality
  , nonCanonicalVcdiffVarintNote
  , edsioVarint
    -- * Lifting raw Binary readers
  , liftRead
  , liftReadVarint
  ) where

import Slap.Binary
  ( VarintResult(..)
  , VarintReadFailure(..)
  , getWord16LE, getWord32LE, getInt16LE, getInt32LE, getInt64LE
  , getWord16BE, getWord24BE, getWord32BE, getInt16BE, getInt32BE, getInt64BE
  , getByuuVarint, getVcdiffVarint
  , minimalVcdiffVarintLength
  , takeLength
  )
import Slap.Measure
  ( Position(..), Length(..), advance, remainingFromPosition
  , RequestedLength(..), RemainingLength(..), ActualLength(..)
  )
import Slap.Status
  ( ByteParserError(..)
  , ByteParserOperation(..)
  , SlapAdvisory(..)
  , SlapError(ParseError)
  )
import Slap.FormatLabel (FormatLabel)

import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Reader (ReaderT(..), ask)
import Control.Monad.Trans.State.Strict
  ( StateT(..), evalStateT, get, put )

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bifunctor (first)
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)

----------------------------------------------------------------------------
-- The ByteParser monad: a standard transformer stack
----------------------------------------------------------------------------

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

-- | Run a parser against an input 'ByteString' starting at offset zero.
-- The final position is discarded.
runByteParser :: ByteParser a -> ByteString -> Either ByteParserError a
runByteParser (ByteParser parser) input =
  runReaderT (evalStateT parser (Position 0)) input

-- | Run a format's body parser, tagging a parse failure as that format's 'ParseError'.
runFormatParser :: FormatLabel -> ByteParser a -> ByteString -> Either SlapError a
runFormatParser label parser input =
  first (ParseError label) (runByteParser parser input)

flattenParse :: Either SlapError (Either SlapError a) -> Either SlapError a
flattenParse = either Left id

parseWhen :: Bool -> ByteParser a -> ByteParser (Maybe a)
parseWhen present parser = if present then Just <$> parser else pure Nothing

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
        (ByteParserNegativeLengthRequestedInGetBytes requestedLength)
  | otherwise = do
      input              <- askInput
      currentPosition    <- ByteParser get
      let inputLength       = ByteString.length input
          Position startAt  = currentPosition
      -- Room is measured by subtraction, never by adding to the request — a wire-wide count cannot wrap
      -- the comparison — and only a count proven to fit is narrowed for the take.
      if count <= fromIntegral (inputLength - startAt)
        then do
          ByteParser (put (advance currentPosition requestedLength))
          pure (takeLength requestedLength (ByteString.drop startAt input))
        else
          throwByteParserError
            (ByteParserUnderflow
                GetBytesOperation
                (RequestedLength requestedLength)
                (RemainingLength (Length (fromIntegral (inputLength - startAt))))
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
        (ByteParserNegativeLengthRequestedInSkip requestedLength)
  | otherwise = do
      input            <- askInput
      currentPosition  <- ByteParser get
      let inputLength      = ByteString.length input
          Position startAt = currentPosition
      if count <= fromIntegral (inputLength - startAt)
        then ByteParser (put (advance currentPosition requestedLength))
        else
          throwByteParserError
            (ByteParserUnderflow
                SkipOperation
                (RequestedLength requestedLength)
                (RemainingLength (Length (fromIntegral (inputLength - startAt))))
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
            (ActualLength (Length (fromIntegral inputLength))))

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
  if width <= fromIntegral (inputLength - startAt)
    then do
      ByteParser (put (advance currentPosition readWidth))
      pure (reader startAt input)
    else
      throwByteParserError
        (ByteParserUnderflow
            FixedWidthReadOperation
            (RequestedLength readWidth)
            (RemainingLength (Length (fromIntegral (inputLength - startAt))))
            currentPosition)

-- | Adapt a pure varint reader, keeping only the decoded value. The over-width verdict is
-- caller-supplied because the readers cross different ceilings; each verdict's constructor says whose.
liftReadVarint :: ByteParserError
               -> (Int -> ByteString -> Either VarintReadFailure VarintResult)
               -> ByteParser Int64
liftReadVarint overWidthVerdict reader =
  varintDecodedValue <$> readVarintAdvancing overWidthVerdict reader

readVarintAdvancing :: ByteParserError
                    -> (Int -> ByteString -> Either VarintReadFailure VarintResult)
                    -> ByteParser VarintResult
readVarintAdvancing overWidthVerdict reader = do
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
      Left VarintTooManyContinuationBytes ->
        throwByteParserError overWidthVerdict
      Left VarintRanPastEndOfInput ->
        throwByteParserError (ByteParserVarintOverranBuffer currentPosition)
      Left VarintExceedsSignedButFitsUnsigned ->
        throwByteParserError ByteParserVarintExceedsSignedRange
      Right result -> do
        ByteParser (put (Position (startAt + varintBytesConsumed result)))
        pure result

word16LE :: ByteParser Word16
word16LE = liftRead (Length 2) getWord16LE

word32LE :: ByteParser Word32
word32LE = liftRead (Length 4) getWord32LE

int16LE :: ByteParser Int64
int16LE = liftRead (Length 2) getInt16LE

int32LE :: ByteParser Int64
int32LE = liftRead (Length 4) getInt32LE

int64LE :: ByteParser Int64
int64LE = liftRead (Length 8) getInt64LE

word16BE :: ByteParser Word16
word16BE = liftRead (Length 2) getWord16BE

word24BE :: ByteParser Word32
word24BE = liftRead (Length 3) getWord24BE

word32BE :: ByteParser Word32
word32BE = liftRead (Length 4) getWord32BE

int16BE :: ByteParser Int64
int16BE = liftRead (Length 2) getInt16BE

int32BE :: ByteParser Int64
int32BE = liftRead (Length 4) getInt32BE

int64BE :: ByteParser Int64
int64BE = liftRead (Length 8) getInt64BE

----------------------------------------------------------------------------
-- Variable-length readers
----------------------------------------------------------------------------

byuuVarint :: ByteParser Int64
byuuVarint = liftReadVarint ByteParserVarintExceedsSignedRange getByuuVarint

vcdiffVarint :: ByteParser Int64
vcdiffVarint = liftReadVarint ByteParserVCDIFFVarintExceedsUnsignedRange getVcdiffVarint

-- | The outcome of reading a VCDIFF varint at the parser seam: the
-- decoded value, plus the overlong-encoding FYI advisory — present
-- only when the encoding was non-canonical. Unlike
-- 'Slap.Binary.VarintResult', which carries the raw consumed-byte
-- count, the seam has already interpreted that count into the advisory.
data VcdiffVarintReading = VcdiffVarintReading
  { vcdiffVarintValue    :: !Int64
  , vcdiffVarintAdvisory :: !(Maybe SlapAdvisory)
  }
  deriving (Show)

nonCanonicalVcdiffVarintNote :: Int64 -> Int -> Maybe SlapAdvisory
nonCanonicalVcdiffVarintNote value consumed
  | consumed > minimalVcdiffVarintLength value = Just (NonCanonicalVCDIFFVarint value)
  | otherwise                                  = Nothing

-- | Read a VCDIFF varint and report whether it was canonically encoded.
-- Plain 'vcdiffVarint' suffices where the encoding's shape doesn't
-- matter; this variant also returns the FYI advisory for an overlong
-- (leading zero-group) encoding. The check is a seam concern, not the
-- reader's: the pure reader reports how many bytes it consumed, and
-- 'nonCanonicalVcdiffVarintNote' turns an over-long span into the note.
vcdiffVarintReportingCanonicality :: ByteParser VcdiffVarintReading
vcdiffVarintReportingCanonicality = do
  result <- readVarintAdvancing ByteParserVCDIFFVarintExceedsUnsignedRange getVcdiffVarint
  let value = varintDecodedValue result
  pure (VcdiffVarintReading value
          (nonCanonicalVcdiffVarintNote value (varintBytesConsumed result)))

-- | EDSIO variable-length unsigned integer, xdelta1's wire encoding: 7 bits per byte, LSB first, high bit = continuation.
-- Decoded inline rather than in 'Slap.Binary' because its continuation discipline matches neither the byuu nor the VCDIFF reader.
-- The 32-bit ceiling is checked once the value is complete, so the verdict can name the whole number rather than a partial accumulation.
edsioVarint :: ByteParser Int64
edsioVarint = accumulate 0 0
  where
    accumulate accumulated bitOffset
      | bitOffset >= 63 =
          throwByteParserError ByteParserEdsioVarintEncodingTooWide
      | otherwise = do
          byte <- getByte
          let value = accumulated .|. (payloadBits byte `shiftL` bitOffset)
          if moreBytesFollow byte
            then accumulate value (bitOffset + 7)
            else closeValue value

    closeValue value
      | value > edsioMaxValue =
          throwByteParserError (ByteParserEdsioVarintExceeds32Bits value)
      | otherwise = pure value

    payloadBits    byte = fromIntegral (byte .&. 0x7F) :: Int64
    moreBytesFollow byte = testBit byte 7

edsioMaxValue :: Int64
edsioMaxValue = 0xFFFFFFFF
