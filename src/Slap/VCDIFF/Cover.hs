-- | A /cover/ is a plan for rebuilding the target: an ordered run of copies and literals.
-- A copy takes a stretch of bytes you already have, a literal writes a few fresh ones, and running them in order rebuilds the target exactly.
--
-- It is its own type to keep two jobs apart: the matcher ('Slap.VCDIFF.FFI.vcdiffCover', Rust-backed) works out the plan, the emitter ('Slap.VCDIFF.Create') turns it into wire bytes.
-- That split keeps a wrong plan (a matcher bug) separate from garbled bytes (an encoder bug).
--
-- A literal holds no bytes: it names a slice of the target.
-- A copy's offset points into the superstring @U@, the same space 'Slap.VCDIFF.Apply' uses, so the two agree on what an address means.
module Slap.VCDIFF.Cover
  ( Cover(..)
  , CoverSegment(..)
  ) where

import Slap.Measure (Offset, Length)

data CoverSegment
  = CoverCopy
      !Length   -- ^ number of bytes copied
      !Offset   -- ^ absolute offset into the superstring @U@
  | CoverLiteral
      !Offset   -- ^ offset into the target where the literal run begins
      !Length   -- ^ length of the literal run
  deriving (Eq, Show)

-- | An ordered list of segments covering the whole target, no gaps or overlaps.
-- The producer upholds that invariant; the emitter trusts it.
newtype Cover = Cover { coverSegments :: [CoverSegment] }
  deriving (Eq, Show)
