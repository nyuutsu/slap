-- | File contents newtypes.
--
-- 'InputFileContents', 'OutputFileContents', and 'PatchFileContents'
-- encode the role each 'ByteString' plays in the patch lifecycle.
-- Apply functions consume an 'InputFileContents' and produce an
-- 'OutputFileContents'. Parse functions consume a 'PatchFileContents'.
-- This prevents the three from being confused at call sites and
-- documents the role of each byte buffer in the type.
--
-- The vocabulary matches slap's CLI flags (@--input@ and @--output@).
-- Individual format specs use other terms — \"source\" and \"target\"
-- (BPS, UPS), \"original\" and \"modified\" (DPS, NINJA2), \"source\"
-- segments (VCDIFF, XDelta1) — and slap preserves those terms inside
-- the format-specific modules where they describe spec-derived
-- concepts. The wrappers here name the cross-format role that's the
-- same regardless of which format is involved.
--
-- All three are newtypes around 'ByteString' with zero runtime cost.
-- Use the @un*@ accessors at boundaries (file I/O, FFI, hash
-- functions) where the underlying 'ByteString' is needed.
module Slap.FileContents
  ( InputFileContents(..)
  , OutputFileContents(..)
  , PatchFileContents(..)
  ) where

import Data.ByteString (ByteString)

-- | The contents of a file before a patch is applied — the input
-- ROM. Format specs and patcher folklore call this the \"source\"
-- or the \"original\"; slap names the role 'InputFileContents' to
-- match its CLI's @--input@ flag.
newtype InputFileContents = InputFileContents
  { unInputFileContents :: ByteString }
  deriving (Eq, Show)

-- | The contents of a file after a patch has been applied — the
-- output ROM. Format specs and patcher folklore call this the
-- \"target\" or the \"modified\" form; slap names the role
-- 'OutputFileContents' to match its CLI's @--output@ flag.
newtype OutputFileContents = OutputFileContents
  { unOutputFileContents :: ByteString }
  deriving (Eq, Show)

-- | The encoded bytes of a patch file itself. This is what parsers
-- consume and creators produce. Distinct from 'InputFileContents'
-- and 'OutputFileContents' so a caller cannot pass a ROM where a
-- patch is expected, or vice versa.
newtype PatchFileContents = PatchFileContents
  { unPatchFileContents :: ByteString }
  deriving (Eq, Show)
