-- | A /cover/ of the target: an ordered segmentation into copies and
-- literals that together reconstruct the target exactly.
--
-- This is the seam between the two halves of VCDIFF creation. The
-- matcher (a later, Rust-backed stage) /produces/ a cover; the emitter
-- ('Slap.VCDIFF.Create') /serializes/ one into wire bytes. Keeping the
-- cover a small, dependency-light type — it knows only 'Offset' and
-- 'Length', never instructions or bytes — lets a future
-- @Slap.VCDIFF.FFI@ fill it without dragging the emitter along, and
-- lets a cover bug and a serialization bug stay distinguishable.
--
-- A literal carries an offset and length /into the target/: the matcher
-- holds the target and names a slice of it rather than copying bytes
-- out. A copy carries a length and an absolute offset into the
-- superstring @U = source ++ produced-target@ — the same space
-- 'Slap.VCDIFF.Apply' resolves a 'Slap.VCDIFF.Types.Copy' against. The
-- matcher does not choose ADD-versus-RUN for a literal; that is
-- instruction selection, and it lives with the emitter.
module Slap.VCDIFF.Cover
  ( Cover(..)
  , CoverSegment(..)
  ) where

import Slap.Measure (Offset, Length)

-- | One segment of a cover.
data CoverSegment
  = CoverCopy
      !Length   -- ^ number of bytes copied
      !Offset   -- ^ absolute offset into the superstring @U = source ++ produced-target@
  | CoverLiteral
      !Offset   -- ^ offset into the target where the literal run begins
      !Length   -- ^ length of the literal run
  deriving (Eq, Show)

-- | An ordered list of segments covering the whole target, in target
-- order, with no gaps or overlaps. The exact-coverage invariant is the
-- producer's to uphold; the emitter trusts it.
newtype Cover = Cover { coverSegments :: [CoverSegment] }
  deriving (Eq, Show)
