{-# LANGUAGE StrictData #-}

-- | The narrowing layer: validate 'SplitHunk's and 'SplitUndoHunk's
-- against per-format offset bounds, producing 'EncodedHunk's and
-- 'EncodedUndoHunk's respectively that downstream encoders can write
-- without silent truncation. Both pipelines compose: a write record
-- passes through 'Slap.Measure.splitHunks' → 'narrowHunks' to reach
-- 'EncodedHunk'; a PPF3 undo record passes through
-- 'Slap.Measure.splitUndoHunks' → 'narrowUndoHunks' to reach
-- 'EncodedUndoHunk'. The discipline is type-enforced — removing
-- either pass from any direct-format pipeline produces a type error.
--
-- 'EncodedHunk' and 'EncodedUndoHunk' are the post-narrow phases of
-- 'SplitHunk' and 'SplitUndoHunk'. Their constructors are private to
-- this module — every encoded value in slap was produced by one of
-- the @narrow*@ functions here. Encoders consume the encoded types
-- through the exported selectors; they cannot construct one. The
-- only way to obtain an 'EncodedHunk' or 'EncodedUndoHunk' is to
-- start with the corresponding split type, which itself can only be
-- obtained from one of the @split*@ functions in "Slap.Measure".
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
  , narrowHunkUnbounded
  , narrowHunksUnbounded
  , narrowUndoHunk
  , narrowUndoHunks
  , narrowUndoHunkUnbounded
  , narrowUndoHunksUnbounded
  ) where

import Data.ByteString (ByteString)

import Slap.FormatLabel (FormatLabel)
import Slap.Measure (Offset(..), SplitHunk, splitOffset, splitPayload,
                     SplitUndoHunk, splitUndoOffset, splitUndoPayload,
                     splitUndoOriginal,
                     ActualOffset(..), MaxOffset(..))

-- | A 'SplitHunk' that has been validated against a format's
-- wire-format offset range (or had that validation explicitly waived
-- for a format whose encoding has no per-record bound — see
-- 'narrowHunkUnbounded'). The constructor is intentionally not
-- exported: every 'EncodedHunk' that exists in slap came from one of
-- the narrow* functions in this module, which in turn can only be
-- handed a 'SplitHunk' produced by the split pass in "Slap.Measure".
data EncodedHunk = EncodedHunk
  { encodedOffset  :: !Offset
  , encodedPayload :: !ByteString
  } deriving (Eq, Show)

-- | The wire-format offset range an encoder can address, paired with
-- the format label used to tag overflow errors. Each format with a
-- bounded per-record offset width defines an 'EncodingLimits' value
-- in its @Types@ module: 'Slap.APSN64.Types.apsN64Limits',
-- 'Slap.PCHTXT.Types.pchtxtLimits', 'Slap.PMSR.Types.pmsrLimits',
-- 'Slap.PPF1.Types.ppf1Limits', 'Slap.PPF2.Types.ppf2Limits',
-- 'Slap.IPS.Types.ipsLimits', 'Slap.IPS.Types.ips32Limits',
-- 'Slap.IPS.Types.ebpLimits'.
data EncodingLimits = EncodingLimits
  { maximumOffset :: !Offset
  , formatLabel   :: !FormatLabel
  } deriving (Show)

-- | The failure space of 'narrowHunk'. A small dedicated sum kept
-- separate from the application-wide 'Slap.Error.SlapError' so this
-- module has no dependency on 'Slap.Error'. The application wraps
-- narrowing failures as 'Slap.Error.NarrowingError' at the boundary
-- where they leave 'Slap.Narrow'.
data NarrowingFailure
  = OffsetExceedsBound !FormatLabel !ActualOffset !MaxOffset
  deriving (Show, Eq)

-- | Narrow a 'SplitHunk' to an 'EncodedHunk' by checking its offset
-- against the format's wire-format range. Overflow surfaces as
-- 'OffsetExceedsBound' tagged with the limits' format label.
narrowHunk :: EncodingLimits -> SplitHunk -> Either NarrowingFailure EncodedHunk
narrowHunk limits hunk
  | unOffset offset > unOffset maximum_ =
      Left (OffsetExceedsBound (formatLabel limits)
                               (ActualOffset offset)
                               (MaxOffset maximum_))
  | otherwise =
      Right EncodedHunk
        { encodedOffset  = offset
        , encodedPayload = splitPayload hunk
        }
  where
    offset   = splitOffset hunk
    maximum_ = maximumOffset limits

narrowHunks :: EncodingLimits -> [SplitHunk] -> Either NarrowingFailure [EncodedHunk]
narrowHunks limits = traverse (narrowHunk limits)

-- | Lift a 'SplitHunk' to an 'EncodedHunk' without validation. Only
-- legitimate for formats whose wire encoding imposes no per-record
-- offset bound — currently NINJA1 (variable-width length-of-offset)
-- and PPF3 (Int64-shaped offset, which any 'Offset' on a 64-bit host
-- already fits).
narrowHunkUnbounded :: SplitHunk -> EncodedHunk
narrowHunkUnbounded hunk = EncodedHunk
  { encodedOffset  = splitOffset hunk
  , encodedPayload = splitPayload hunk
  }

narrowHunksUnbounded :: [SplitHunk] -> [EncodedHunk]
narrowHunksUnbounded = map narrowHunkUnbounded

-- | A 'SplitUndoHunk' that has been validated against a format's
-- wire-format offset range (or had that validation explicitly waived
-- via 'narrowUndoHunkUnbounded'). Constructor private; the only way
-- to obtain one is to narrow a 'SplitUndoHunk', which itself can
-- only be obtained from one of the @split*@ functions in
-- "Slap.Measure". Parallel to 'EncodedHunk' for undo records.
data EncodedUndoHunk = EncodedUndoHunk
  { encodedUndoOffset   :: !Offset
  , encodedUndoPayload  :: !ByteString
  , encodedUndoOriginal :: !ByteString
  } deriving (Eq, Show)

-- | Narrow a 'SplitUndoHunk' to an 'EncodedUndoHunk' by checking its
-- offset against the format's wire-format range. Overflow surfaces
-- as 'OffsetExceedsBound' tagged with the limits' format label.
narrowUndoHunk :: EncodingLimits -> SplitUndoHunk -> Either NarrowingFailure EncodedUndoHunk
narrowUndoHunk limits hunk
  | unOffset offset > unOffset maximum_ =
      Left (OffsetExceedsBound (formatLabel limits)
                               (ActualOffset offset)
                               (MaxOffset maximum_))
  | otherwise =
      Right EncodedUndoHunk
        { encodedUndoOffset   = offset
        , encodedUndoPayload  = splitUndoPayload hunk
        , encodedUndoOriginal = splitUndoOriginal hunk
        }
  where
    offset   = splitUndoOffset hunk
    maximum_ = maximumOffset limits

narrowUndoHunks :: EncodingLimits -> [SplitUndoHunk] -> Either NarrowingFailure [EncodedUndoHunk]
narrowUndoHunks limits = traverse (narrowUndoHunk limits)

-- | Lift a 'SplitUndoHunk' to an 'EncodedUndoHunk' without
-- validation. Only legitimate for formats whose wire encoding
-- imposes no per-record offset bound — currently PPF3 alone, whose
-- Int64-shaped offset on the wire fits any 'Offset' on a 64-bit host.
narrowUndoHunkUnbounded :: SplitUndoHunk -> EncodedUndoHunk
narrowUndoHunkUnbounded hunk = EncodedUndoHunk
  { encodedUndoOffset   = splitUndoOffset hunk
  , encodedUndoPayload  = splitUndoPayload hunk
  , encodedUndoOriginal = splitUndoOriginal hunk
  }

narrowUndoHunksUnbounded :: [SplitUndoHunk] -> [EncodedUndoHunk]
narrowUndoHunksUnbounded = map narrowUndoHunkUnbounded
