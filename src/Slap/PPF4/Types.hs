{-# LANGUAGE OverloadedStrings #-}

module Slap.PPF4.Types
  ( PPF4Patch(..)
  , PPF4Replace(..)
  , PPF4Append(..)
  , ppf4HeaderLength
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
-- PPF1/2/3 facts and live on 'Slap.PPF.Types.PPFPatch'.
data PPF4Patch = PPF4Patch
  { ppf4Description :: !ByteString
  , ppf4Replaces    :: ![PPF4Replace]
  , ppf4Appends     :: ![PPF4Append]
  } deriving (Show)

-- | A PPF4 Replace record: writes 'replaceData' at 'replaceOffset' in
-- the target. Replace records cannot grow the file; the offset must be
-- in @[0, sourceFileSize)@. (Bug 1 in slap today: this range check is
-- not enforced at apply time. The follow-up commit adds it.)
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

-- | PPF4 header length in bytes.
ppf4HeaderLength :: Length
ppf4HeaderLength = Length 60

-- | Length of the flag/padding bytes after the description field in a
-- PPF4 header. Per Pyriel's source: image_type (1) + validation_flag (1)
-- + undo_flag (1) + expansion (1).
ppf4PostDescriptionLength :: Length
ppf4PostDescriptionLength = Length 4
