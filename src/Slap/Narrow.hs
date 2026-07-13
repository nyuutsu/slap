{-# LANGUAGE StrictData #-}

-- | The narrowing layer: validate 'SplitHunk's and 'SplitUndoHunk's against per-format offset bounds,
-- producing 'EncodedHunk's and 'EncodedUndoHunk's that downstream encoders can write without silent truncation or a negative write position.
-- Both pipelines compose: a write record passes through 'Slap.Measure.splitHunks' → 'narrowHunks' to reach 'EncodedHunk';
-- a PPF3 undo record passes through 'Slap.Measure.splitUndoHunks' → 'narrowUndoHunks' to reach 'EncodedUndoHunk'.
-- The discipline is type-enforced: removing either pass from any direct-format pipeline produces a type error.
module Slap.Narrow
  ( EncodedHunk
  , encodedOffset
  , encodedPayload
  , EncodedUndoHunk
  , encodedUndoOffset
  , encodedUndoPayload
  , encodedUndoOriginal
  , EncodingLimits(..)
  , NarrowingFailure(..)
  , narrowHunk
  , narrowHunks
  , narrowUndoHunk
  , narrowUndoHunks
  , narrowToWord32
  , narrowToWord16
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word16, Word32)

import Slap.FieldName (FieldName)
import Slap.FormatLabel (FormatLabel)
import Slap.Measure (Offset(..), SplitHunk, splitOffset, splitPayload,
                     SplitUndoHunk, splitUndoOffset, splitUndoPayload,
                     splitUndoOriginal,
                     ActualOffset(..), MaxOffset(..))

-- | A 'SplitHunk' whose offset 'narrowHunk' has checked non-negative and within the format's maximum.
-- The constructor is not exported, so every 'EncodedHunk' carries that guarantee.
data EncodedHunk = EncodedHunk
  { encodedOffset  :: !Offset
  , encodedPayload :: !ByteString
  } deriving (Eq, Show)

-- | The wire-format offset range an encoder can address,
-- paired with the format label used to tag overflow errors.
-- Each format with a bounded per-record offset width defines one in its @Types@ module;
-- 'Slap.Convert.encodingLimits' is the table that maps each direct target to its value.
data EncodingLimits = EncodingLimits
  { maximumOffset :: !Offset
  , formatLabel   :: !FormatLabel
  } deriving (Show)

-- | The failure space of the narrowing layer. A small dedicated sum
-- kept separate from the application-wide 'Slap.Status.SlapError' so
-- this module has no dependency on 'Slap.Status'. The application
-- wraps narrowing failures as 'Slap.Status.NarrowingError' at the
-- boundary where they leave 'Slap.Narrow'.
data NarrowingFailure
  = OffsetExceedsBound !FormatLabel !ActualOffset !MaxOffset
  | NegativeOffset !FormatLabel !ActualOffset
    -- ^ A record offset is negative; encoding it would 'fromIntegral'-wrap into a large unsigned value and silently misplace the write.
    -- The source is a parsed PPF3 patch, whose offset is a signed @int64@ on the wire (spec, @PPF3.txt@):
    -- a high-bit value decodes to a negative 'Offset', which apply rejects ('Slap.Status.ApplyNegativeRecordOffset')
    -- and convert to a bounded target refuses here.
  | FieldValueExceedsBound !FormatLabel !FieldName !Integer !Integer
    -- ^ A header or trailer field's runtime value exceeded the
    -- wire-format width of the field. The two 'Integer's are the
    -- actual value and the field's maximum (kept as 'Integer' so any
    -- 'Word' width fits without further wrapping).
  deriving (Show, Eq)

-- | Narrow an integer to 'Word32', producing 'FieldValueExceedsBound'
-- if the value is negative or exceeds @0xFFFFFFFF@. Used by per-format
-- @narrow*@ smart constructors that wire a runtime integer (file size,
-- list length, bytestring length) into a typed wrapper whose
-- constructor is private.
narrowToWord32 :: Integral value => FormatLabel -> FieldName -> value -> Either NarrowingFailure Word32
narrowToWord32 label field value
  | value < 0 || toInteger value > toInteger maxValue =
      Left (FieldValueExceedsBound label field
              (toInteger value) (toInteger maxValue))
  | otherwise = Right (fromIntegral value)
  where
    maxValue :: Word32
    maxValue = maxBound

-- | 'Word16' counterpart, ceiling @0xFFFF@.
narrowToWord16 :: FormatLabel -> FieldName -> Int -> Either NarrowingFailure Word16
narrowToWord16 label field value
  | value < 0 || toInteger value > toInteger maxValue =
      Left (FieldValueExceedsBound label field
              (toInteger value) (toInteger maxValue))
  | otherwise = Right (fromIntegral value)
  where
    maxValue :: Word16
    maxValue = maxBound

-- | Narrow a 'SplitHunk' to an 'EncodedHunk' by checking its offset
-- against the format's wire-format range: non-negative (a write
-- position cannot be negative), and within the format's maximum.
narrowHunk :: EncodingLimits -> SplitHunk -> Either NarrowingFailure EncodedHunk
narrowHunk limits hunk
  | unOffset offset < 0 =
      Left (NegativeOffset (formatLabel limits) (ActualOffset offset))
  | unOffset offset > unOffset maximumEncodableOffset =
      Left (OffsetExceedsBound (formatLabel limits)
                               (ActualOffset offset)
                               (MaxOffset maximumEncodableOffset))
  | otherwise =
      Right EncodedHunk
        { encodedOffset  = offset
        , encodedPayload = splitPayload hunk
        }
  where
    offset   = splitOffset hunk
    maximumEncodableOffset = maximumOffset limits

narrowHunks :: EncodingLimits -> [SplitHunk] -> Either NarrowingFailure [EncodedHunk]
narrowHunks limits = traverse (narrowHunk limits)

-- | The undo-record parallel of 'EncodedHunk': a 'SplitUndoHunk' whose offset 'narrowUndoHunk' has checked.
-- Its constructor is private for the same reason.
data EncodedUndoHunk = EncodedUndoHunk
  { encodedUndoOffset   :: !Offset
  , encodedUndoPayload  :: !ByteString
  , encodedUndoOriginal :: !ByteString
  } deriving (Eq, Show)

-- | Narrow a 'SplitUndoHunk' to an 'EncodedUndoHunk' by checking its
-- offset against the format's wire-format range: non-negative and
-- within the maximum, the same two-sided check as 'narrowHunk'.
narrowUndoHunk :: EncodingLimits -> SplitUndoHunk -> Either NarrowingFailure EncodedUndoHunk
narrowUndoHunk limits hunk
  | unOffset offset < 0 =
      Left (NegativeOffset (formatLabel limits) (ActualOffset offset))
  | unOffset offset > unOffset maximumEncodableOffset =
      Left (OffsetExceedsBound (formatLabel limits)
                               (ActualOffset offset)
                               (MaxOffset maximumEncodableOffset))
  | otherwise =
      Right EncodedUndoHunk
        { encodedUndoOffset   = offset
        , encodedUndoPayload  = splitUndoPayload hunk
        , encodedUndoOriginal = splitUndoOriginal hunk
        }
  where
    offset   = splitUndoOffset hunk
    maximumEncodableOffset = maximumOffset limits

narrowUndoHunks :: EncodingLimits -> [SplitUndoHunk] -> Either NarrowingFailure [EncodedUndoHunk]
narrowUndoHunks limits = traverse (narrowUndoHunk limits)
