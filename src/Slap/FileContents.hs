-- | File contents newtypes.
--
-- 'SourceFileContents' and 'TargetFileContents' encode the role each
-- 'ByteString' plays in the patch lifecycle. Apply functions consume
-- a 'SourceFileContents' and produce a 'TargetFileContents'. This
-- prevents the two from being confused at call sites and documents
-- the role of each byte buffer in the type.
--
-- Both are newtypes around 'ByteString' with zero runtime cost.
-- Use 'unSourceFileContents' and 'unTargetFileContents' at boundaries
-- (file I\/O, FFI, hash functions) where the underlying 'ByteString'
-- is needed.
module Slap.FileContents
  ( SourceFileContents(..)
  , TargetFileContents(..)
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
