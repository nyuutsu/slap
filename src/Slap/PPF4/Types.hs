{-# LANGUAGE OverloadedStrings #-}

module Slap.PPF4.Types
  ( PPF4Patch(..)
  , PPF4Replace(..)
  , PPF4Append(..)
  , ppf4MagicBytes
  , ppf4HeaderLength
  , ppf4PreambleLength
  , ppf4DescriptionLength
  , ppf4PostDescriptionLength
  ) where

import Data.ByteString (ByteString)
import Slap.Measure (Offset, Length(..))

-- | A fully parsed PPF4 patch.
--
-- PPF4 is a two-phase format: REPLACE records first, then ADD records,
-- with a one-way phase transition. The two phases are reflected as
-- separate fields on this record. The wire-format ordering — all
-- Replace records before any Append record — is enforced at parse
-- time; values of this type are guaranteed to satisfy that invariant.
--
-- PPF4 has no validation block, no source CRC, no file-size advisory,
-- no undo data, no image type, no File_ID.diz trailer. Those are
-- PPF1/2/3 facts that live on each format's per-version Patch type.
data PPF4Patch = PPF4Patch
  { ppf4Description :: !ByteString
  , ppf4Replaces    :: ![PPF4Replace]
  , ppf4Appends     :: ![PPF4Append]
  } deriving (Show)

-- | A PPF4 Replace record: writes 'replaceData' at 'replaceOffset' in
-- the target. Replace records cannot grow the file; the offset plus
-- the payload length must be in @[0, sourceFileSize]@. Enforced at
-- apply time by 'Slap.PPF4.Apply.applyPPF4', which fails with
-- 'Slap.Status.ApplyReplaceGrowsFile' on violation.
data PPF4Replace = PPF4Replace
  { replaceOffset :: !Offset
  , replaceData   :: !ByteString
  } deriving (Show)

-- | A PPF4 Append record: writes 'appendData' at the end of the file
-- (where "end" is captured before any apply work begins; Replaces
-- cannot extend the file). The wire format spends 4 bytes on a
-- per-record offset field that is dropped at parse time — Append
-- records have no meaningful offset, and the type does not carry the
-- discarded wire bytes.
newtype PPF4Append = PPF4Append { appendData :: ByteString }
  deriving (Show)

-- | Wire-format magic prefix: ASCII @"PPF4"@.
ppf4MagicBytes :: ByteString
ppf4MagicBytes = "PPF4"

-- | PPF4 header length in bytes.
ppf4HeaderLength :: Length
ppf4HeaderLength = Length 60

-- | Length of the header preamble before the description field:
-- magic (4) + version (1) + encoding (1).
ppf4PreambleLength :: Length
ppf4PreambleLength = Length 6

-- | Length of the description field: 50 bytes (matches PPF1/PPF2/PPF3
-- coincidentally; the PPF4 spec ships the same width independently).
ppf4DescriptionLength :: Length
ppf4DescriptionLength = Length 50

-- | Length of the flag/padding bytes after the description field in a
-- PPF4 header. Per Pyriel's source: image_type (1) + validation_flag (1)
-- + undo_flag (1) + expansion (1).
ppf4PostDescriptionLength :: Length
ppf4PostDescriptionLength = Length 4
