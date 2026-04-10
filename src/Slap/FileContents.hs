-- | File contents newtypes.
--
-- 'SourceFileContents', 'TargetFileContents', and 'PatchFileContents'
-- encode the role each 'ByteString' plays in the patch lifecycle.
-- Apply functions consume a 'SourceFileContents' and produce a
-- 'TargetFileContents'. Parse functions consume a 'PatchFileContents'.
-- This prevents the three from being confused at call sites and
-- documents the role of each byte buffer in the type.
--
-- All three are newtypes around 'ByteString' with zero runtime cost.
-- Use the @un*@ accessors at boundaries (file I\/O, FFI, hash
-- functions) where the underlying 'ByteString' is needed.
module Slap.FileContents
  ( SourceFileContents(..)
  , TargetFileContents(..)
  , PatchFileContents(..)
  ) where

import Data.ByteString (ByteString)

-- | The contents of a file before a patch is applied. The "source"
-- in patch terminology — equivalently, the "original."
newtype SourceFileContents = SourceFileContents
  { unSourceFileContents :: ByteString }
  deriving (Eq, Show)

-- | The contents of a file after a patch has been applied. The
-- "target" or "modified" form.
newtype TargetFileContents = TargetFileContents
  { unTargetFileContents :: ByteString }
  deriving (Eq, Show)

-- | The encoded bytes of a patch file itself. This is what parsers
-- consume and creators produce. Distinct from 'SourceFileContents'
-- and 'TargetFileContents' so a caller cannot pass a ROM where a
-- patch is expected, or vice versa.
newtype PatchFileContents = PatchFileContents
  { unPatchFileContents :: ByteString }
  deriving (Eq, Show)
