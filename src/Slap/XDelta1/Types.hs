{-# LANGUAGE StrictData #-}

module Slap.XDelta1.Types
  ( XDelta1Patch(..)
  , XDelta1Source(..)
  , XDelta1SourceShape(..)
  , xdelta1FileSourceOf
  , XDelta1Instruction(..)
  , XDelta1Version(..)
  , fromXDelta1Version
  , XDelta1SourceKind(..)
  , XDelta1OffsetMode(..)
    -- * Named constants
  , xdelta1TrailerSize
  ) where

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Slap.Checksum (MD5Hash(..))
import Slap.Measure (Offset(..), FileSize(..))

data XDelta1Version = XDelta1v104 | XDelta1v11
  deriving (Show, Eq)

fromXDelta1Version :: XDelta1Version -> String
fromXDelta1Version XDelta1v104 = "1.0.4"
fromXDelta1Version XDelta1v11  = "1.1"

data XDelta1SourceKind = FileSource | DataSegmentSource
  deriving (Show, Eq)

data XDelta1OffsetMode = AbsoluteOffsets | SequentialOffsets
  deriving (Show, Eq)

data XDelta1Patch = XDelta1Patch
  { xdelta1Version      :: XDelta1Version
  , xdelta1FromName     :: ByteString
  , xdelta1ToName       :: ByteString
  , xdelta1ToMD5        :: MD5Hash
  , xdelta1TargetLength :: FileSize
  , xdelta1SourceShape  :: XDelta1SourceShape
  , xdelta1Instructions :: [XDelta1Instruction]
  , xdelta1DataSegment  :: ByteString  -- decompressed literal data
  } deriving (Show, Eq)

data XDelta1Source = XDelta1Source
  { xdelta1SourceName       :: ByteString
  , xdelta1SourceMD5        :: MD5Hash
  , xdelta1SourceLength     :: FileSize
  , xdelta1SourceKind       :: XDelta1SourceKind
  , xdelta1SourceOffsetMode :: XDelta1OffsetMode
  } deriving (Show, Eq)

-- | The four source-list shapes the xdelta1 spec admits, encoded
-- precisely. The wire encodes the source list as a varint-prefixed
-- sequence of records (EDSIO's general list shape), so any count is
-- structurally parseable; the spec narrows that field to four
-- configurations. Both author-produced authorities — the canonical
-- tool ('xdmain.c:1741-1768', error @EC_XdIncompatibleDelta@) and
-- the xdelta.1 manpage (MacDonald 2001 — single-fromfile
-- single-tofile synopses for both @delta@ and @patch@ subcommands)
-- — confirm at-most-one-file-source. Shapes outside these four are
-- rejected by 'Slap.XDelta1.Parse.parseXDelta1' with
-- 'Slap.Error.UnsupportedXDelta1Shape'.
data XDelta1SourceShape
  = XDelta1NoSources
    -- ^ Empty source list. Instructions targeting any index would
    -- be malformed; the parser additionally validates that an
    -- 'XDelta1NoSources' patch carries no instructions.
  | XDelta1DataOnly XDelta1Source
    -- ^ One data segment at index 0, no file source. The single
    -- 'XDelta1Source' has @'xdelta1SourceKind' = 'DataSegmentSource'@.
  | XDelta1FileOnly XDelta1Source
    -- ^ One file source at index 0, no data segment. The single
    -- 'XDelta1Source' has @'xdelta1SourceKind' = 'FileSource'@.
  | XDelta1DataAndFile XDelta1Source XDelta1Source
    -- ^ Data segment at index 0, file source at index 1. The
    -- normal case for real-world patches. The first
    -- 'XDelta1Source' has 'DataSegmentSource' kind, the second
    -- has 'FileSource'.
  deriving (Show, Eq)

-- | The patch's file source, if any. Total over all four shapes;
-- replaces a @filter (\\e -> kind e == FileSource) sources@ +
-- first-of pattern at every consumer that needs the source MD5.
xdelta1FileSourceOf :: XDelta1SourceShape -> Maybe XDelta1Source
xdelta1FileSourceOf XDelta1NoSources                  = Nothing
xdelta1FileSourceOf (XDelta1DataOnly _)               = Nothing
xdelta1FileSourceOf (XDelta1FileOnly fileSource)      = Just fileSource
xdelta1FileSourceOf (XDelta1DataAndFile _ fileSource) = Just fileSource

data XDelta1Instruction = XDelta1Instruction
  { xdelta1InstructionIndex  :: Int64     -- array index, stays Int64
  , xdelta1InstructionOffset :: Offset
  , xdelta1InstructionLength :: FileSize
  } deriving (Show, Eq)

-- | Trailer size: 4-byte control offset + 8-byte trailing magic.
xdelta1TrailerSize :: Int
xdelta1TrailerSize = 12
