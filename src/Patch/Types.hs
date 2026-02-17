{-# LANGUAGE StrictData #-}

module Patch.Types
  ( PatchFormat(..)
  , SomePatch(..)
  , ChecksumResult(..)
  , checksumOk
  ) where

import Data.Word (Word32)

import qualified Patch.PPF.Types as PPF

-- | Detected patch format.
data PatchFormat = FmtPPF
  deriving (Show, Eq)

-- | A parsed patch of any supported format.
data SomePatch
  = SomePPF PPF.Patch

-- | Result of a checksum comparison.
data ChecksumResult
  = CrcMatch
  | CrcMismatch String Word32 Word32  -- label, expected, actual
  deriving (Show)

checksumOk :: ChecksumResult -> Bool
checksumOk CrcMatch = True
checksumOk _        = False
