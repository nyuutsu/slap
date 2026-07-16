{-# LANGUAGE DerivingVia #-}
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
import Slap.Status.Render.Advisory (plural)
import Slap.Status.Vocabulary (slapAddressableCeiling)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), ActionIndex(unActionIndex),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ExpectedSize(..))

import Data.Aeson (ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

-- | Which of BPS's two independent relative cursors underflowed:
-- the source cursor ('SourceCopy' reads) or the target cursor ('TargetCopy' reads).
data CursorKind = SourceCursor | TargetCursor
  deriving (Show, Eq, Generic)
  deriving (ToJSON) via Generically CursorKind

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

  -- | An absolute wire write position whose payload runs past the target's end — the start alone can sit past it,
  -- unlike 'ApplyWritesPastTarget' and its always-in-buffer forward cursor.
  | ApplyAbsoluteWritePastTarget ActionIndex Offset RequestedLength FileSize

  deriving (Show, Eq, Generic)
  deriving (ToJSON) via Generically ApplyError

renderCursorKind :: CursorKind -> Text
renderCursorKind SourceCursor = "source-relative"
renderCursorKind TargetCursor = "target-relative"

renderApplyError :: ApplyError -> Text

renderApplyError (ApplyCursorUnderflow cursorKind actionIndex cursor) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " reads from before the start of the " <> addressedFile
  <> " (the " <> renderCursorKind cursorKind <> " cursor lands at "
  <> renderAsText (unSignedOffset cursor) <> ")"
  where
    addressedFile = case cursorKind of
      SourceCursor -> "input"
      TargetCursor -> "output"

renderApplyError (ApplySourceReadOutOfBounds actionIndex readEndOffset sourceSize) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " reads past the end of the input (the input ends at offset 0x"
  <> renderHexAsText (unFileSize sourceSize)
  <> "; this read runs to 0x" <> renderHexAsText (unOffset readEndOffset) <> ")"

renderApplyError (ApplyTargetReadUnwritten actionIndex (ReadOffset readOffset) (WritePosition writePosition)) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> ": the patch copies from a part of the output it hasn't produced yet"
  <> " (a TargetCopy reads at offset 0x" <> renderHexAsText (unOffset readOffset)
  <> ", but the output ends at 0x" <> renderHexAsText (unOffset writePosition)
  <> " so far)"

renderApplyError (ApplyWritesPastTarget actionIndex (RequestedLength requestedLength) (RemainingLength remainingLength)) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " writes " <> renderAsText (unLength requestedLength)
  <> plural (unLength requestedLength) " byte" " bytes"
  <> ", with only " <> renderAsText (unLength remainingLength)
  <> " left in the output"

renderApplyError (ApplyTargetUnderfilled (WritePosition cursor) (ExpectedSize expectedSize)) =
  "the patch ends before the output is complete ("
  <> renderAsText (unOffset cursor) <> " of "
  <> renderAsText (unFileSize expectedSize) <> " bytes written)"

renderApplyError (ApplyNegativeRecordOffset actionIndex offset) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " writes at offset " <> renderAsText (unOffset offset)

renderApplyError (ApplyNegativeControlLength actionIndex (RequestedLength regionLength)) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " declares a region length of " <> renderAsText (unLength regionLength)
  <> " bytes; a record's seek may be negative, but a length may not"

renderApplyError (ApplyOutputExceedsAddressableRange actionIndex offset payloadLength) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " writes at offset " <> renderAsText (unOffset offset)
  <> " plus " <> renderAsText (unLength payloadLength)
  <> " bytes, reaching "
  <> renderAsText (toInteger (unOffset offset) + toInteger (unLength payloadLength))
  <> "; that is past " <> slapAddressableCeiling
  <> ", the largest position slap can address"

renderApplyError (ApplyReplaceGrowsFile actionIndex offset (RequestedLength payloadLength) sourceSize) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " writes past the end of the input (a Replace at offset 0x"
  <> renderHexAsText (unOffset offset)
  <> " writes " <> renderAsText (unLength payloadLength)
  <> plural (unLength payloadLength) " byte" " bytes"
  <> ", running past the input's "
  <> renderAsText (unFileSize sourceSize) <> "-byte end;"
  <> " a Replace cannot grow the file, only an Append can)"

renderApplyError (ApplyDiffReadOutOfBounds actionIndex readEndOffset diffSize) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " reads past the end of the patch's data (the diff block, which holds the changed bytes, ends at offset 0x"
  <> renderHexAsText (unFileSize diffSize)
  <> "; this read runs to 0x" <> renderHexAsText (unOffset readEndOffset) <> ")"

renderApplyError (ApplyExtraReadOutOfBounds actionIndex readEndOffset extraSize) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " reads past the end of the patch's data (the extra block, which holds the brand-new bytes, ends at offset 0x"
  <> renderHexAsText (unFileSize extraSize)
  <> "; this read runs to 0x" <> renderHexAsText (unOffset readEndOffset) <> ")"

renderApplyError (ApplyAbsoluteWritePastTarget actionIndex writeStart (RequestedLength payloadLength) targetSize) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " writes " <> renderAsText (unLength payloadLength)
  <> plural (unLength payloadLength) " byte" " bytes"
  <> " at offset 0x" <> renderHexAsText (unOffset writeStart)
  <> ", running past the output's "
  <> renderAsText (unFileSize targetSize) <> "-byte end"
