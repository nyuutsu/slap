{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | The byte-parser failures, and their voice.
module Slap.Status.ByteParserError
  ( ByteParserOperation(..)
  , ByteParserError(..)
  , renderByteParserError
  ) where

import Slap.Display.Common (renderAsText)
import Slap.Display.Primitives (padHex)
import Slap.FieldName (FieldName, fieldNameLabel)
import Slap.Measure (Length(..), Position(..), ActionIndex(unActionIndex),
                     RequestedLength(..), RemainingLength(..),
                     RequiredLength(..), ActualLength(..))

import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Word (Word8, Word32)
import Numeric (showHex)

-- | Which primitive of 'Slap.ByteParser' surfaced an underflow, for 'ByteParserUnderflow'.
data ByteParserOperation
  = GetBytesOperation
  | SkipOperation
  | FixedWidthReadOperation
  | VarintReadOperation
  deriving (Eq, Show)

-- | The structured failure type for 'Slap.ByteParser.ByteParser',
-- lifted into 'Slap.Status.SlapError' via 'Slap.Status.ParseError' with the wrapping format's 'Slap.FormatLabel.FormatLabel'.
data ByteParserError

  -- | A read asked for 'RequestedLength' bytes at 'Position' with only 'RemainingLength' left.
  = ByteParserUnderflow ByteParserOperation RequestedLength RemainingLength Position

  -- | A record declares more bytes than the stream holds. Format walkers raise it ahead of the doomed read,
  -- so the failure names the record and its full declared size ('RequiredLength', header included)
  -- rather than the byte offset a raw underflow would have named.
  | ByteParserTruncatedRecord !ActionIndex !RequiredLength !RemainingLength

  -- | A command-coded stream's next code byte is outside the format's command table.
  | ByteParserUnknownCommandByte !ActionIndex !Word8

  -- | A width-prefixed integer field decoded a value past 'maxBound' :: 'Int' — the sibling of 'ByteParserVarintExceededWidth'.
  -- The width prefix has no ceiling, so the wire can name a value no 'Int' holds;
  -- the reader decodes at 'Integer' and declines rather than wrapping. The 'ActionIndex' names the record and the 'FieldName' which field.
  | ByteParserFieldExceedsAddressableRange !ActionIndex !FieldName

  -- | 'Slap.ByteParser.getUntilByte' scanned from 'Position' to end of input without finding the terminator byte.
  | ByteParserTerminatorNotFound Word8 Position

  -- | A 'Slap.ByteParser.setPosition' target outside @[0, inputLength]@.
  | ByteParserPositionOutOfBounds Position ActualLength

  -- | 'Slap.ByteParser.getBytes' was asked for a negative count. Split from the 'Slap.ByteParser.skip' variant below
  -- because only those two primitives accept a caller-supplied length; the fixed-width and varint reads cannot produce this failure.
  | ByteParserNegativeLengthRequestedInGetBytes Length

  -- | 'Slap.ByteParser.skip' was asked to advance by a negative count.
  | ByteParserNegativeLengthRequestedInSkip Length

  -- | A varint started inside the buffer but its continuation bytes ran past the end; the 'Position' is where it started.
  -- Distinct from 'ByteParserUnderflow' at 'VarintReadOperation', which fires when the read started at or past EOF.
  | ByteParserVarintOverranBuffer Position

  -- | A varint decoded a value too large to represent at all. All three varint readers (byuu, VCDIFF, EDSIO) raise it;
  -- for VCDIFF it means a value at or past @2^64@, beyond even xd3's @uint64@ —
  -- the @[2^63, 2^64)@ band is the separate 'ByteParserVarintExceedsSignedRange'.
  | ByteParserVarintExceededWidth

  -- | A VCDIFF varint decoded a value in @[2^63, 2^64)@ — xd3's unsigned reader accepts it, slap's signed 'Int' cannot.
  -- Kept apart from 'ByteParserVarintExceededWidth' so the renderer can concede the one bit slap gives up rather than blame the input.
  | ByteParserVarintExceedsSignedRange

  -- | An EDSIO varint decoded a value past @0xFFFFFFFF@. Every integer in the xdelta1 wire format is a @guint32@ (upstream @xd_edsio.h@),
  -- so a wider value is not a representable xdelta1 quantity; canonical xdelta truncates such a value silently, slap declines it.
  | ByteParserEdsioVarintExceeds32Bits !Int64

  -- | The xdelta1 control segment opened with a type tag that isn't @ST_XdeltaControl@.
  -- Canonical's EDSIO reader rejects an unregistered library number (the tag's low byte) with "Unregistered library: N";
  -- slap declines the same way. The 'Word32' is the tag as read.
  | ByteParserXDelta1UnexpectedControlTypeTag !Word32

  -- | The 'MonadFail' fallback for @do@-pattern failures in parser code.
  -- Reaching this arm means slap has a bug, not that the wire input was malformed.
  | ByteParserUnexpectedDoPatternFailure String

  deriving (Eq, Show)

byteParserOperationLabel :: ByteParserOperation -> Text
byteParserOperationLabel GetBytesOperation        = "getBytes"
byteParserOperationLabel SkipOperation            = "skip"
byteParserOperationLabel FixedWidthReadOperation  = "fixed-width read"
byteParserOperationLabel VarintReadOperation      = "varint read"

renderByteParserError :: ByteParserError -> Text

renderByteParserError
  (ByteParserUnderflow
      operation
      (RequestedLength (Length requested))
      (RemainingLength (Length available))
      (Position cursor)) =
  byteParserOperationLabel operation
  <> ": need " <> renderAsText requested <> " bytes at offset " <> renderAsText cursor
  <> " but only " <> renderAsText available <> " available"

renderByteParserError
  (ByteParserTruncatedRecord
      recordIndex
      (RequiredLength (Length needed))
      (RemainingLength (Length available))) =
  "record " <> renderAsText (unActionIndex recordIndex)
  <> " truncated (need " <> renderAsText needed
  <> " bytes, have " <> renderAsText available <> ")"

renderByteParserError (ByteParserUnknownCommandByte recordIndex commandByte) =
  "record " <> renderAsText (unActionIndex recordIndex)
  <> ": unknown command byte 0x" <> padHex 2 commandByte

renderByteParserError (ByteParserFieldExceedsAddressableRange recordIndex field) =
  "record " <> renderAsText (unActionIndex recordIndex)
  <> ": " <> fieldNameLabel field <> " past the "
  <> renderAsText (maxBound :: Int) <> "-byte limit slap can address"

renderByteParserError (ByteParserTerminatorNotFound terminatorByte (Position cursor)) =
  "getUntilByte: terminator 0x" <> padHex 2 terminatorByte
  <> " not found from offset " <> renderAsText cursor

renderByteParserError
  (ByteParserPositionOutOfBounds (Position target) (ActualLength (Length inputLength))) =
  "setPosition: " <> renderAsText target
  <> " out of bounds (input length " <> renderAsText inputLength <> ")"

renderByteParserError
  (ByteParserNegativeLengthRequestedInGetBytes (Length amount)) =
  "getBytes: negative length " <> renderAsText amount

renderByteParserError
  (ByteParserNegativeLengthRequestedInSkip (Length amount)) =
  "skip: negative length " <> renderAsText amount

renderByteParserError (ByteParserVarintOverranBuffer (Position cursor)) =
  "varint read overran buffer at offset " <> renderAsText cursor

renderByteParserError ByteParserVarintExceededWidth =
  "varint overflow (too many continuation bytes)"

renderByteParserError ByteParserVarintExceedsSignedRange =
  "varint decoded a value in [2^63, 2^64): xd3 admits it as an unsigned"
  <> " uint64, but slap carries sizes as a signed Int and declines it"

renderByteParserError (ByteParserEdsioVarintExceeds32Bits value) =
  "EDSIO varint decoded " <> renderAsText value
  <> ", past the 0xFFFFFFFF ceiling of xdelta1's 32-bit fields"

renderByteParserError (ByteParserXDelta1UnexpectedControlTypeTag observedTag) =
  "xdelta1 control segment opens with type tag 0x" <> Text.pack (showHex observedTag "")
  <> ", not ST_XdeltaControl; canonical's EDSIO reader rejects an unregistered library number "
  <> "(the tag's low byte) with \"Unregistered library: N\""

renderByteParserError (ByteParserUnexpectedDoPatternFailure message) =
  "internal: do-pattern match failed in slap's parser: " <> Text.pack message
