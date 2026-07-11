{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | The format-agnostic apply failures, and their voice.
module Slap.Status.ApplyError
  ( CursorKind(..)
  , ApplyError(..)
  , renderCursorKind
  , renderApplyError
  ) where

import Slap.Display.Common (renderAsText, renderHexAsText)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), ActionIndex(unActionIndex),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ExpectedSize(..))

import Data.Text (Text)

-- | Which of BPS's two independent relative cursors underflowed:
-- the source cursor ('SourceCopy' reads) or the target cursor ('TargetCopy' reads).
data CursorKind = SourceCursor | TargetCursor
  deriving (Show, Eq)

-- | Format-agnostic errors from patch application, paired with a 'Slap.FormatLabel.FormatLabel' via 'Slap.Status.ApplyFailed'.
-- Most variants carry the 'ActionIndex' of the action that triggered them.
data ApplyError

  -- | A relative cursor (source or target) went negative after applying the action's delta.
  = ApplyCursorUnderflow CursorKind ActionIndex SignedOffset

  -- | An action would read past the end of the source ByteString.
  -- The 'Offset' is the would-be read end; the 'FileSize' is the actual source size.
  | ApplySourceReadOutOfBounds ActionIndex Offset FileSize

  -- | A TargetCopy referenced an output position at or past the write head — bytes not yet written.
  | ApplyTargetReadUnwritten ActionIndex ReadOffset WritePosition

  -- | An action's output length would exceed the remaining space in the target buffer.
  | ApplyWritesPastTarget ActionIndex RequestedLength RemainingLength

  -- | The action stream was exhausted but the target buffer is not fully written.
  -- No 'ActionIndex': this fires after the stream ends, with no specific action responsible — the whole patch is short.
  -- (No corresponding @ApplyTargetOverfilled@: 'ApplyWritesPastTarget' catches over-writes per-action before they can happen.)
  | ApplyTargetUnderfilled WritePosition ExpectedSize

  -- | A record's offset is negative. Possible only where the offset encoding admits one:
  -- PPF3's signed 64-bit field, and NINJA2's packed integers, which decode into a signed 'Int'.
  | ApplyNegativeRecordOffset ActionIndex Offset

  -- | A bsdiff control instruction declares a negative region length — bsdiff's sign-magnitude wire encoding admits one,
  -- but a region length is non-negative by nature. (The seek delta in the same triple is legitimately signed and is not this.)
  | ApplyNegativeControlLength ActionIndex RequestedLength

  -- | A record's write end — offset plus payload length — exceeds 'maxBound' :: 'Int', the ceiling of slap's position carrier.
  -- Only a wire offset as wide as the carrier (PPF3's signed 64-bit field) can name such a write;
  -- the format admits it, and slap declines to materialise an output it cannot address.
  -- The apply-side sibling of 'Slap.Status.FileExceedsAddressableRange'.
  -- The 'Offset' and 'Length' are carried separately because it is their sum that does not fit; the renderer adds them in 'Integer'.
  | ApplyOutputExceedsAddressableRange ActionIndex Offset Length

  -- | A PPF4 Replace record would write past the source's end. Replace cannot grow the file — only Append can;
  -- the reference applier rejects this with @ERROR_BAD_SIZE@.
  | ApplyReplaceGrowsFile ActionIndex Offset RequestedLength FileSize

  -- | A BSDiff ADD instruction would read past the end of the diff stream.
  -- The 'Offset' is the would-be read end; the 'FileSize' is the diff stream's size.
  | ApplyDiffReadOutOfBounds ActionIndex Offset FileSize

  -- | The extra-stream mirror of 'ApplyDiffReadOutOfBounds', for BSDiff COPY.
  | ApplyExtraReadOutOfBounds ActionIndex Offset FileSize

  -- | A record's wire-declared absolute write position plus payload extends past the declared target end ('FileSize').
  -- For formats that name absolute positions on the wire — NINJA2's XOR records and overflow-append step, APSGBA's blocks —
  -- where the start alone can already sit past the end,
  -- unlike 'ApplyWritesPastTarget', whose forward-walking cursor always sits within the buffer.
  | ApplyAbsoluteWritePastTarget ActionIndex Offset RequestedLength FileSize

  deriving (Show, Eq)

renderCursorKind :: CursorKind -> Text
renderCursorKind SourceCursor = "source-relative"
renderCursorKind TargetCursor = "target-relative"

renderApplyError :: ApplyError -> Text

renderApplyError (ApplyCursorUnderflow cursorKind actionIndex cursor) =
  "at step #" <> renderAsText (unActionIndex actionIndex) <> ": "
  <> renderCursorKind cursorKind <> " cursor underflowed (value "
  <> renderAsText (unSignedOffset cursor) <> ")"

renderApplyError (ApplySourceReadOutOfBounds actionIndex readEndOffset sourceSize) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": input read would end at offset 0x"
  <> renderHexAsText (unOffset readEndOffset)
  <> " but input is " <> renderAsText (unFileSize sourceSize) <> " bytes"

renderApplyError (ApplyTargetReadUnwritten actionIndex (ReadOffset readOffset) (WritePosition writePosition)) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": TargetCopy read at offset 0x"
  <> renderHexAsText (unOffset readOffset)
  <> " references position at or past current write position 0x"
  <> renderHexAsText (unOffset writePosition)

renderApplyError (ApplyWritesPastTarget actionIndex (RequestedLength requestedLength) (RemainingLength remainingLength)) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": action of length " <> renderAsText (unLength requestedLength)
  <> " would write past output ("
  <> renderAsText (unLength remainingLength) <> " bytes remaining)"

renderApplyError (ApplyTargetUnderfilled (WritePosition cursor) (ExpectedSize expectedSize)) =
  "output under-filled ("
  <> renderAsText (unOffset cursor) <> " of "
  <> renderAsText (unFileSize expectedSize) <> " bytes written before action stream exhausted)"

renderApplyError (ApplyNegativeRecordOffset actionIndex offset) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " has negative offset " <> renderAsText (unOffset offset)

renderApplyError (ApplyNegativeControlLength actionIndex (RequestedLength regionLength)) =
  "control instruction " <> renderAsText (unActionIndex actionIndex)
  <> " declares a negative region length " <> renderAsText (unLength regionLength)

renderApplyError (ApplyOutputExceedsAddressableRange actionIndex offset payloadLength) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " writes at offset " <> renderAsText (unOffset offset)
  <> " plus " <> renderAsText (unLength payloadLength)
  <> " bytes, reaching "
  <> renderAsText (toInteger (unOffset offset) + toInteger (unLength payloadLength))
  <> " — past the " <> renderAsText (maxBound :: Int)
  <> "-byte limit slap can address"

renderApplyError (ApplyReplaceGrowsFile actionIndex offset (RequestedLength payloadLength) sourceSize) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> ": Replace at offset 0x" <> renderHexAsText (unOffset offset)
  <> " writes " <> renderAsText (unLength payloadLength) <> " bytes"
  <> ", which would extend past the source size of "
  <> renderAsText (unFileSize sourceSize) <> " bytes"
  <> " (PPF4 Replaces cannot grow the file; use Append records)"

renderApplyError (ApplyDiffReadOutOfBounds actionIndex readEndOffset diffSize) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": diff-stream read would end at offset 0x"
  <> renderHexAsText (unOffset readEndOffset)
  <> " but diff stream is " <> renderAsText (unFileSize diffSize) <> " bytes"

renderApplyError (ApplyExtraReadOutOfBounds actionIndex readEndOffset extraSize) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": extra-stream read would end at offset 0x"
  <> renderHexAsText (unOffset readEndOffset)
  <> " but extra stream is " <> renderAsText (unFileSize extraSize) <> " bytes"

renderApplyError (ApplyAbsoluteWritePastTarget actionIndex writeStart (RequestedLength payloadLength) targetSize) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> ": write at offset 0x" <> renderHexAsText (unOffset writeStart)
  <> " of " <> renderAsText (unLength payloadLength) <> " bytes"
  <> " would extend past the target size of "
  <> renderAsText (unFileSize targetSize) <> " bytes"
