-- | File contents newtypes.
--
-- 'InputFileContents', 'OutputFileContents', and 'PatchFileContents' encode the role each 'ByteString' plays in the patch lifecycle, so a caller cannot confuse a ROM with a patch, or input with output.
-- Apply consumes an 'InputFileContents' and produces an 'OutputFileContents'; parse consumes a 'PatchFileContents'.
-- The names match slap's @--input@ and @--output@ flags; format-specific modules keep their own spec vocabulary where it describes spec-derived concepts.
--
-- Use the @un*@ accessors at boundaries (file I/O, FFI, hash functions) where the underlying 'ByteString' is needed.
module Slap.FileContents
  ( InputFileContents(..)
  , OutputFileContents(..)
  , PatchFileContents(..)
  ) where

import Data.ByteString (ByteString)

-- | The contents of a file before a patch is applied — the input ROM.
-- Format specs call it the "source" or "original".
newtype InputFileContents = InputFileContents
  { unInputFileContents :: ByteString }
  deriving (Eq, Show)

-- | The contents of a file after a patch has been applied — the output ROM.
-- Format specs call it the "target" or "modified".
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
