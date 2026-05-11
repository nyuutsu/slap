{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.XDelta1.Types
  ( XDelta1Patch(..)
  , XDelta1Source(..)
  , XDelta1SourceShape(..)
  , xdelta1FileSourceOf
  , XDelta1Instruction(..)
  , XDelta1SourceKind(..)
  , XDelta1OffsetMode(..)
  , XDelta1VerificationPosture(..)
    -- * Named constants
  , xdelta1TrailerSize
  , xdelta1EmptyInputMD5Sentinel
  ) where

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Slap.Checksum (MD5Hash(..))
import Slap.Measure (Offset(..), FileSize(..))

data XDelta1SourceKind = FileSource | DataSegmentSource
  deriving (Show, Eq)

data XDelta1OffsetMode = AbsoluteOffsets | SequentialOffsets
  deriving (Show, Eq)

data XDelta1Patch = XDelta1Patch
  { xdelta1FromName      :: ByteString
  , xdelta1ToName        :: ByteString
  , xdelta1Verification  :: XDelta1VerificationPosture
  , xdelta1TargetLength  :: FileSize
  , xdelta1SourceShape   :: XDelta1SourceShape
  , xdelta1Instructions  :: [XDelta1Instruction]
  , xdelta1DataSegment   :: ByteString  -- decompressed literal data
  } deriving (Show, Eq)

-- | An xdelta1 source record. The 'xdelta1SourceMD5' is 'Just' when
-- the enclosing 'XDelta1Patch' has posture 'VerifyAgainstStoredMD5s'
-- (the MD5 carried real verification data on the wire) and 'Nothing'
-- when the posture is 'CreatorOptedOutOfVerification' (the wire
-- carried 'xdelta1EmptyInputMD5Sentinel' or another non-trusted
-- placeholder; the parser discards it rather than letting it reach
-- 'Slap.SomePatch.Verification'). The invariant — every source in a
-- patch shares the patch-level posture's @Just@/@Nothing@ — is by
-- parser construction; not type-enforced. Consumers pattern-match
-- on @Just@/@Nothing@ and handle both arms (never @fromJust@), the
-- same discipline PPF3 follows for 'Slap.PPF3.Types.ppf3RecordUndo'.
data XDelta1Source = XDelta1Source
  { xdelta1SourceName       :: ByteString
  , xdelta1SourceMD5        :: Maybe MD5Hash
  , xdelta1SourceLength     :: FileSize
  , xdelta1SourceKind       :: XDelta1SourceKind
  , xdelta1SourceOffsetMode :: XDelta1OffsetMode
  } deriving (Show, Eq)

-- | The slap-internal representation of an xdelta 1.1.x patch's
-- verification posture — whether MD5 fields carry real verification
-- data or are the canonical sentinel ('xdelta1EmptyInputMD5Sentinel')
-- emitted by the canonical tool's @--noverify@. Designed as the
-- round-trip vehicle for the @--no-verify@ family in xdelta1: the
-- parser today produces a value of this type from the wire; the
-- future xdelta1 create flow (when @slap create --no-verify@ lands)
-- will consume a value of this type and write the corresponding
-- wire bytes (flag bit set with sentinels in MD5 slots, or flag bit
-- clear with computed MD5s). Constructors are unchanged across
-- directions. Family siblings: 'VerificationPolicy' on apply (the
-- runtime policy that gates mismatch behavior when verification
-- /does/ run), 'Slap.Error.VerificationOptedOutByCreator' (the
-- warning emitted when verification is declared absent at the
-- format level).
data XDelta1VerificationPosture
  = VerifyAgainstStoredMD5s !MD5Hash
  | CreatorOptedOutOfVerification
  deriving (Show, Eq)

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

-- | The MD5 of zero input bytes
-- (@d41d8cd98f00b204e9800998ecf8427e@), used by xdelta 1.1.x's
-- canonical tool as the placeholder in every MD5 slot of a patch
-- created with @--noverify@. The bytes are written by an
-- @edsio_md5_init@ + 0× @_update@ + @_final@ sequence
-- (@xdmain.c:1055,1075,1301@), forced by the algorithm to produce
-- this fixed value. Non-canonical producers may write other bytes;
-- the constant is named here so future diagnostic code can
-- reference the canonical sentinel by name rather than inline hex.
xdelta1EmptyInputMD5Sentinel :: MD5Hash
xdelta1EmptyInputMD5Sentinel = MD5Hash
  "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"
