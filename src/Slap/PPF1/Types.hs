{-# LANGUAGE OverloadedStrings #-}

-- | Types for PPF1 patches. PPF1 is the original Paradox patch format,
-- specified in @docs/ppf/upstream/pdx-ppf1/ppf-doc.txt@: a 56-byte
-- header (magic + version + encoding byte + 50-byte description)
-- followed by an open-ended stream of records, where each record is
-- a 4-byte LE offset, a 1-byte count, and either @count@ payload
-- bytes (literal mode) or — when the count byte is zero — a 2-byte
-- @(data_byte, repeat_count)@ pair (RLE mode).
module Slap.PPF1.Types
  ( PPF1Patch(..)
  , PPF1Record(..)
  , PPF1Origin(..)
    -- * Named constants
  , ppf1MagicBytes
  , ppf1DescriptionLength
  , ppf1HeaderLength
  , ppf1MaxRecordPayload
  ) where

import Data.ByteString (ByteString)
import Slap.Measure (Length(..), Offset)

-- | A single PPF1 record. Both literal and RLE forms expand to the
-- same in-memory shape: a target-file offset and the bytes to write
-- there. The wire-level RLE encoding is decoded at parse time.
data PPF1Record = PPF1Record
  { ppf1RecordOffset  :: !Offset
  , ppf1RecordPayload :: !ByteString
  } deriving (Show)

-- | A fully parsed PPF1 patch. PPF1 carries no validation block, no
-- undo data, no FILE_ID.DIZ — just a description and records.
data PPF1Patch = PPF1Patch
  { ppf1Description :: !ByteString  -- ^ 50-byte description, raw on-wire bytes (space- or null-padded)
  , ppf1Records     :: ![PPF1Record]
  } deriving (Show)

-- | Whether a PPF1 patch's offset fields are PC-origin (little-endian)
-- or Amiga-origin (big-endian). The on-wire format does not encode
-- which: the producer's host platform decides at create time, and the
-- reader has to know out-of-band. Slap defaults to 'PPF1OriginPC';
-- the @--is-amiga-patch@ CLI flag selects 'PPF1OriginAmiga'.
--
-- Threaded into 'Slap.PPF1.Parse.parsePPF1' (controlling the @word32LE@
-- vs @word32BE@ branch on offset reads) and 'Slap.PPF1.Create.encodePPF1'
-- (the symmetric branch on offset writes). Apply consumes 'PPF1Patch''s
-- canonical 'Offset' values and is dialect-blind.
data PPF1Origin = PPF1OriginPC | PPF1OriginAmiga
  deriving (Show, Eq)

-- | Wire-format magic prefix: ASCII @"PPF1"@.
ppf1MagicBytes :: ByteString
ppf1MagicBytes = "PPF1"

-- | Length of the description field: 50 bytes.
ppf1DescriptionLength :: Length
ppf1DescriptionLength = Length 50

-- | Total PPF1 header length: 4 magic + 1 version + 1 encoding + 50 description = 56.
ppf1HeaderLength :: Length
ppf1HeaderLength = Length 56

-- | Maximum payload bytes a single PPF1 record can carry. The record
-- format uses a single-byte count field (literal mode), capping
-- payload at @0xFF = 255@.
ppf1MaxRecordPayload :: Length
ppf1MaxRecordPayload = Length 255
