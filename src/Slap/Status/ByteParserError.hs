{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | The byte-parser failures, and their voice.
module Slap.Status.ByteParserError
  ( ByteParserOperation(..)
  , ByteParserError(..)
  , renderByteParserError
  ) where

import Slap.Display.Common (renderAsText, renderHexAsText)
import Slap.Display.Primitives (padHex)
import Slap.Status.Render.Advisory (plural)
import Slap.Status.Vocabulary (slapAddressableCeiling)
import Slap.FieldName (FieldName, fieldNameLabel)
import Slap.Measure (Length(..), Position(..), ActionIndex(unActionIndex),
                     RequestedLength(..), RemainingLength(..),
                     RequiredLength(..), ActualLength(..))

import Data.Aeson (ToJSON)
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Word (Word8, Word32)
import GHC.Generics (Generic, Generically(..))
import Numeric (showHex)

-- | Which primitive of 'Slap.ByteParser' surfaced an underflow, for 'ByteParserUnderflow'.
data ByteParserOperation
  = GetBytesOperation
  | SkipOperation
  | FixedWidthReadOperation
  | VarintReadOperation
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically ByteParserOperation

-- | The structured failure type for 'Slap.ByteParser.ByteParser',
-- lifted into 'Slap.Status.SlapError' via 'Slap.Status.ParseError' with the wrapping format's 'Slap.FormatLabel.FormatLabel'.
data ByteParserError

  -- | A read asked for 'RequestedLength' bytes at 'Position' with only 'RemainingLength' left.
  = ByteParserUnderflow ByteParserOperation RequestedLength RemainingLength Position

  -- | A record declares more bytes than the stream holds. Format walkers raise it ahead of the doomed read,
  -- so the failure names the record and its full declared size ('RequiredLength', header included)
  -- rather than the byte offset a raw underflow would have named.
  | ByteParserTruncatedRecord !ActionIndex !RequiredLength !RemainingLength

  -- | The stream ends with bytes too few to begin a record — some remain where the next record's header would sit, but fewer than a whole record needs.
  -- Distinct from 'ByteParserTruncatedRecord', whose record read far enough to declare a size the rest of the stream then failed to meet.
  -- The 'RequiredLength' is the smallest a record of this format can be; the 'RemainingLength' is what was stranded.
  | ByteParserTrailingBytesTooFewForRecord !ActionIndex !RequiredLength !RemainingLength

  -- | A command-coded stream's next code byte is outside the format's command table.
  | ByteParserUnknownCommandByte !ActionIndex !Word8

  -- | A width-prefixed integer field decoded a value past 'maxBound' :: 'Int' — the sibling of 'ByteParserVarintExceedsSignedRange'.
  -- The width prefix has no ceiling, so the wire can name a value no 'Int' holds;
  -- the reader decodes at 'Integer' and declines rather than wrapping.
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

  -- | A VCDIFF varint decoded a value at or past @2^64@, beyond even xd3's unsigned @uint64@;
  -- the @[2^63, 2^64)@ band is 'ByteParserVarintExceedsSignedRange'.
  | ByteParserVCDIFFVarintExceedsUnsignedRange

  -- | A varint decoded a value at or past @2^63@ — slap's ceiling, not necessarily the wire's.
  -- Kept apart from 'ByteParserVCDIFFVarintExceedsUnsignedRange' so the renderer can concede the range slap gives up rather than blame the input.
  | ByteParserVarintExceedsSignedRange

  -- | An EDSIO varint decoded a value past @0xFFFFFFFF@. Every integer in the xdelta1 wire format is a @guint32@ (upstream @xd_edsio.h@),
  -- so a wider value is not a representable xdelta1 quantity; canonical xdelta truncates such a value silently, slap declines it.
  | ByteParserEdsioVarintExceeds32Bits !Int64

  -- | An EDSIO varint's encoding ran past nine continuation bytes.
  -- A zero-padded overlong encoding of a small number lands here too.
  | ByteParserEdsioVarintEncodingTooWide

  -- | The xdelta1 control segment opens with a type tag other than 'Slap.XDelta1.Types.xdelta1ControlTypeTag',
  -- whose comment holds the tag's full story. The 'Word32' is the tag as read.
  | ByteParserXDelta1UnexpectedControlTypeTag !Word32

  -- | The 'MonadFail' fallback for @do@-pattern failures in parser code.
  -- Reaching this arm means slap has a bug, not that the wire input was malformed.
  | ByteParserUnexpectedDoPatternFailure String

  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically ByteParserError

byteParserOperationNounPhrase :: ByteParserOperation -> Text
byteParserOperationNounPhrase GetBytesOperation        = "a read"
byteParserOperationNounPhrase SkipOperation            = "a skip"
byteParserOperationNounPhrase FixedWidthReadOperation  = "a fixed-width field"
byteParserOperationNounPhrase VarintReadOperation      = "a variable-width integer"

renderByteParserError :: ByteParserError -> Text

renderByteParserError
  (ByteParserUnderflow
      operation
      (RequestedLength (Length requested))
      (RemainingLength (Length available))
      (Position cursor)) =
  "the patch runs out of bytes ("
  <> byteParserOperationNounPhrase operation
  <> " at offset 0x" <> renderHexAsText cursor
  <> " needs " <> renderAsText requested <> plural requested " byte" " bytes"
  <> ", with only " <> renderAsText available <> " left)"

renderByteParserError
  (ByteParserTruncatedRecord
      recordIndex
      (RequiredLength (Length needed))
      (RemainingLength (Length available))) =
  "record " <> renderAsText (unActionIndex recordIndex)
  <> " is truncated (it declares " <> renderAsText needed
  <> plural needed " byte" " bytes"
  <> ", with only " <> renderAsText available <> " left in the patch)"

renderByteParserError
  (ByteParserTrailingBytesTooFewForRecord
      recordIndex
      (RequiredLength (Length needed))
      (RemainingLength (Length available))) =
  "the patch ends with " <> renderAsText available
  <> plural available " trailing byte" " trailing bytes"
  <> ", too few to form record " <> renderAsText (unActionIndex recordIndex)
  <> " (a record needs at least " <> renderAsText needed <> ")"

renderByteParserError (ByteParserUnknownCommandByte recordIndex commandByte) =
  "record " <> renderAsText (unActionIndex recordIndex)
  <> " begins with an instruction the format does not define (command byte 0x"
  <> padHex 2 commandByte <> ")"

renderByteParserError (ByteParserFieldExceedsAddressableRange recordIndex field) =
  "record " <> renderAsText (unActionIndex recordIndex)
  <> ": the " <> fieldNameLabel field <> " names a value past "
  <> slapAddressableCeiling <> ", the largest slap can hold"

renderByteParserError (ByteParserTerminatorNotFound terminatorByte (Position cursor)) =
  "a field starting at offset 0x" <> renderHexAsText cursor
  <> " never ends (no 0x" <> padHex 2 terminatorByte
  <> " terminator between there and the end of the patch)"

renderByteParserError
  (ByteParserPositionOutOfBounds (Position target) (ActualLength (Length inputLength))) =
  "the patch seeks to offset 0x" <> renderHexAsText target
  <> ", but the patch is only " <> renderAsText inputLength
  <> plural inputLength " byte" " bytes"

renderByteParserError
  (ByteParserNegativeLengthRequestedInGetBytes (Length amount)) =
  "the patch asks to read " <> renderAsText amount <> " bytes"

renderByteParserError
  (ByteParserNegativeLengthRequestedInSkip (Length amount)) =
  "the patch asks to skip " <> renderAsText amount <> " bytes;"
  <> " a skip is a length to pass over, not a signed move,"
  <> " so a negative one is not a rewind but a value with no meaning"

renderByteParserError (ByteParserVarintOverranBuffer (Position cursor)) =
  "a number in the patch is cut short (a variable-width integer starting at offset 0x"
  <> renderHexAsText cursor <> " runs past the end of the patch)"

renderByteParserError ByteParserVCDIFFVarintExceedsUnsignedRange =
  "a number in the patch is 2^64 or more, past what any VCDIFF reader holds"
  <> " (xdelta3 carries these as unsigned 64-bit integers; this one needs more than 64 bits)"

renderByteParserError ByteParserVarintExceedsSignedRange =
  "a number in the patch is 2^63 or more; the format can express"
  <> " a number that needs the 64th bit, but slap cannot"

renderByteParserError (ByteParserEdsioVarintExceeds32Bits value) =
  "a number in the patch decodes to " <> renderAsText value
  <> "; every integer in the format is 32 bits, so no value past 0xFFFFFFFF can be meant"

renderByteParserError ByteParserEdsioVarintEncodingTooWide =
  "a number in the patch is encoded in more than nine bytes;"
  <> " the format's integers are 32 bits, which fit in five"

renderByteParserError (ByteParserXDelta1UnexpectedControlTypeTag observedTag) =
  "the patch doesn't say what to do (the control segment, where the instructions live,"
  <> " is malformed: it should open with type tag 0x8003 and instead opens with 0x"
  <> Text.pack (showHex observedTag "") <> ")"

renderByteParserError (ByteParserUnexpectedDoPatternFailure message) =
  "slap hit a bug in its own parser; this is slap's fault, not your patch's."
  <> " Please report it: " <> Text.pack message
