{-# LANGUAGE StrictData #-}

-- | The narrowing layer: validate that 'SplitHunk's fit a format's
-- wire-format offset bound, producing 'EncodedHunk's that downstream
-- encoders can write without silent truncation.
--
-- 'EncodedHunk' is the post-narrow phase of a 'SplitHunk'. Its
-- constructor is private to this module — every 'EncodedHunk' value
-- in slap was produced by 'narrowHunk', 'narrowHunks',
-- 'narrowHunkUnbounded', or 'narrowHunksUnbounded'. Encoders consume
-- 'EncodedHunk' through the exported selectors; they cannot
-- construct one. The discipline "every encoded record went through
-- both split (or 'splitHunksUnbounded') and narrow (or
-- 'narrowHunksUnbounded')" is type-enforced rather than
-- conventional: the only way to obtain an 'EncodedHunk' is to start
-- with a 'SplitHunk', which itself can only be obtained from one of
-- the @split*@ functions in "Slap.Measure". Removing either pass
-- from any direct-format pipeline produces a type error.
module Slap.Narrow
  ( EncodedHunk
  , encodedOffset
  , encodedPayload
  , EncodingLimits(..)
  , NarrowingFailure(..)
  , narrowHunk
  , narrowHunks
  , narrowHunkUnbounded
  , narrowHunksUnbounded
  ) where

import Data.ByteString (ByteString)

import Slap.FormatLabel (FormatLabel)
import Slap.Measure (Offset(..), SplitHunk, splitOffset, splitPayload,
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
-- in its @Types@ module (see 'Slap.APSN64.Types.apsN64Limits',
-- 'Slap.PCHTXT.Types.pchtxtLimits', 'Slap.PMSR.Types.pmsrLimits',
-- 'Slap.PPF1.Types.ppf1Limits', 'Slap.PPF2.Types.ppf2Limits' for the
-- direct family; 'Slap.IPS.Types.variantSpec' threads through to one
-- of these for each IPS variant).
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
