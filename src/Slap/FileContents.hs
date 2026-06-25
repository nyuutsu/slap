-- | The file-contents role newtypes: apply consumes 'InputFileContents' and produces 'OutputFileContents'; parse consumes 'PatchFileContents'.
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
