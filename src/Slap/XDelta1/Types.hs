{-# LANGUAGE OverloadedStrings #-}

module Slap.XDelta1.Types
  ( XDelta1Patch(..)
  , XDelta1Source(..)
  , XDelta1Sources(..)
  , XDelta1Instruction(..)
  , XDelta1InstructionTarget(..)
  , XDelta1OffsetMode(..)
  , XDelta1SourceWireKind(..)
  , XDelta1VerificationPosture(..)
  , XDelta1PatchCompression(..)
  , XDelta1FileAtDeltaTime(..)
    -- * Named constants
  , xdelta1TrailerSize
  , xdelta1EmptyInputMD5Sentinel
  , xdelta1FlagNoVerify
  , xdelta1FlagFromCompressed
  , xdelta1FlagToCompressed
  , xdelta1FlagPatchCompressed
  , xdelta1ControlTypeTag
  , xdelta1ControlAllocationBound
  ) where

import Data.Bits (shiftL)
import Data.ByteString (ByteString)
import Data.Word (Word32)
import Slap.Checksum (MD5Hash(..))
import Slap.Measure (Offset(..), FileSize(..))

data XDelta1OffsetMode = AbsoluteOffsets | SequentialOffsets
  deriving (Show, Eq)

-- | The two values the wire format's source-kind byte can carry,
-- named at the type level. Used by "Slap.XDelta1.Parse" to
-- classify the byte during parse and by "Slap.XDelta1.Create" to
-- write the byte during create. The wire convention is byte @1@
-- for 'WireKindData' and byte @0@ for 'WireKindFile' — canonical
-- xdelta's @xdelta.c:246@ writes the data source at index 0 with
-- kind byte 1, and @xdmain.c:1539-1542@ adds the from-file source
-- at index 1 with kind byte 0.
data XDelta1SourceWireKind
  = WireKindData
  | WireKindFile
  deriving (Show, Eq)

data XDelta1Patch = XDelta1Patch
  { xdelta1FromName         :: ByteString
  , xdelta1ToName           :: ByteString
  , xdelta1Verification     :: XDelta1VerificationPosture
  , xdelta1PatchCompression :: XDelta1PatchCompression
  , xdelta1FromAtDeltaTime  :: XDelta1FileAtDeltaTime
  , xdelta1ToAtDeltaTime    :: XDelta1FileAtDeltaTime
  , xdelta1TargetLength     :: FileSize
  , xdelta1Sources          :: XDelta1Sources
  , xdelta1Instructions     :: [XDelta1Instruction]
  , xdelta1DataSegment      :: ByteString  -- decompressed literal data
  } deriving (Show, Eq)

-- | An xdelta1 source record. The 'xdelta1SourceMD5' is 'Just' when
-- the enclosing 'XDelta1Patch' has posture 'VerifyAgainstStoredMD5s'
-- and 'Nothing' when the posture is 'CreatorOptedOutOfVerification';
-- see 'XDelta1VerificationPosture' for the invariant.
--
-- The role (data segment vs file source) is determined by which
-- field of 'XDelta1Sources' the record occupies — there is no
-- per-source kind field, and there is no representable state where
-- a source could be in the wrong slot.
data XDelta1Source = XDelta1Source
  { xdelta1SourceName       :: ByteString
  , xdelta1SourceMD5        :: Maybe MD5Hash
  , xdelta1SourceLength     :: FileSize
  , xdelta1SourceOffsetMode :: XDelta1OffsetMode
  } deriving (Show, Eq)

-- | The two-source list xdelta1 patches carry: one data segment
-- (instructions referencing it copy from the patch's inline data
-- bytes) followed by one file source (instructions referencing it
-- copy from the user's external source file). The order is wire-
-- significant — index 0 is the data source, index 1 is the file
-- source — and matches what canonical xdelta emits unconditionally
-- ('xdelta-1.1.4/xdelta.c:241-251' adds the data source, then
-- 'xdmain.c:1539-1542' adds the from-file source). The parser
-- refuses any other source-list configuration with
-- 'Slap.Error.UnsupportedXDelta1Shape'.
data XDelta1Sources = XDelta1Sources
  { xdelta1DataSource :: XDelta1Source
  , xdelta1FileSource :: XDelta1Source
  } deriving (Show, Eq)

-- | The slap-internal representation of an xdelta 1.1.x patch's
-- verification posture — whether MD5 fields carry real verification
-- data or are the canonical sentinel ('xdelta1EmptyInputMD5Sentinel')
-- emitted by the canonical tool's @--noverify@. The round-trip
-- vehicle for the @--no-verify@ family in xdelta1: the parser
-- produces a value of this type from the wire; the encoder in
-- "Slap.XDelta1.Create" consumes one (mapped from
-- 'Slap.Convert.VerificationInclusion' at the porcelain boundary)
-- and writes the corresponding wire bytes (flag bit set with
-- sentinels in MD5 slots, or flag bit clear with computed MD5s).
-- Constructors are unchanged across directions. Per-source MD5s
-- share the patch-level posture: both sources in 'XDelta1Sources'
-- carry @Just MD5Hash@ under 'VerifyAgainstStoredMD5s' and
-- @Nothing@ under 'CreatorOptedOutOfVerification' (parser-
-- enforced; not type-level). Family siblings:
-- 'Slap.Convert.VerificationInclusion' on create (the user-facing
-- choice the porcelain maps to a posture), 'VerificationPolicy'
-- on apply (the runtime policy that gates mismatch behavior when
-- verification /does/ run),
-- 'Slap.Error.VerificationOptedOutByCreator' (the warning emitted
-- when verification is declared absent at the format level).
data XDelta1VerificationPosture
  = VerifyAgainstStoredMD5s MD5Hash
  | CreatorOptedOutOfVerification
  deriving (Show, Eq)

-- | Whether an xdelta1 patch's data and control segments are gzip-
-- compressed in the wire bytes. Bit 3 ('xdelta1FlagPatchCompressed')
-- of the header's flags word; the parser inflates each segment
-- independently when the bit is set. Uncompressed @%XDZ004%@
-- patches are spec-conformant; canonical xdelta-1.x emits
-- compressed by default. Slap follows that default on create and
-- gates the choice on @slap create --no-compress@.
data XDelta1PatchCompression
  = CompressedPatch
  | UncompressedPatch
  deriving (Show, Eq)

-- | Whether one of the two files involved in delta computation was
-- a gzip stream at the time the patch was created. Canonical xdelta
-- detects gzip-magic input and transparently decompresses it before
-- computing the delta; the matching flag bit
-- ('xdelta1FlagFromCompressed' bit 1, 'xdelta1FlagToCompressed'
-- bit 2) tells the apply tool to do the inverse transparency on
-- its side. Slap doesn't implement that transparency today; apply
-- refuses with 'Slap.Error.XDelta1InputPreCompressionUnsupported'
-- when either side is 'FileWasGzipStream', rather than silently
-- producing wrong output against the user's literal source bytes.
data XDelta1FileAtDeltaTime
  = FileWasRawBytes
  | FileWasGzipStream
  deriving (Show, Eq)

-- | Which of the patch's two sources an instruction copies from.
-- The wire format encodes this as an integer index (0 for the data
-- source, 1 for the file source); the parser translates the wire
-- byte to this sum at parse time and refuses any other index with
-- 'Slap.Error.XDelta1UnknownInstructionTarget'. Apply-side
-- dispatch ('Slap.XDelta1.Apply.applyXDelta1') pattern-matches on
-- this rather than threading the raw integer through.
data XDelta1InstructionTarget
  = FromDataSource
  | FromFileSource
  deriving (Show, Eq)

data XDelta1Instruction = XDelta1Instruction
  { xdelta1InstructionTarget :: XDelta1InstructionTarget
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

-- | Bit 0 of the xdelta1 header's flags word. Set when the patch's
-- verification posture is 'CreatorOptedOutOfVerification' (matching
-- what canonical xdelta's @--noverify@ writes).
xdelta1FlagNoVerify :: Word32
xdelta1FlagNoVerify = 1

-- | Bit 1 of the xdelta1 header's flags word. Set when the from-
-- file was detected as a gzip stream at delta time by the canonical
-- tool, which decompressed it transparently before computing the
-- delta (and expects the apply tool to do the same on its side).
xdelta1FlagFromCompressed :: Word32
xdelta1FlagFromCompressed = 2

-- | Bit 2 of the xdelta1 header's flags word. Set when the to-
-- file was detected as a gzip stream at delta time by the canonical
-- tool, which decompressed it transparently before computing the
-- delta (and expects the apply tool to re-compress the output).
xdelta1FlagToCompressed :: Word32
xdelta1FlagToCompressed = 4

-- | Bit 3 of the xdelta1 header's flags word. Set when the patch's
-- data and control segments are gzip-deflated in the wire bytes
-- (each segment is its own gzip stream).
xdelta1FlagPatchCompressed :: Word32
xdelta1FlagPatchCompressed = 8

-- | EDSIO type tag for canonical xdelta's @ST_XdeltaControl@ record
-- type. Derived from @tools\/xdelta1\/xdelta-1.1.4\/xd_edsio.h:108@:
--
-- @
-- ST_XdeltaControl = (1 << (7 + EDSIO_LIBRARY_OFFSET_BITS)) + 3
-- @
--
-- with @EDSIO_LIBRARY_OFFSET_BITS = 8@ from
-- @tools\/xdelta1\/xdelta-1.1.4\/libedsio\/edsio.h:41@. The low byte
-- (3) is the library number canonical validates at
-- @libedsio\/generic.c:66@ — a literal-zero library bails with
-- "Unregistered library: 0", which is the symptom slap-made patches
-- produced before this constant was wired in; the high bits identify
-- the type within that library. Big-endian on the wire, occupying
-- bytes 0..3 of the EDSIO-serialized control segment.
xdelta1ControlTypeTag :: Word32
xdelta1ControlTypeTag = (1 `shiftL` 15) + 3  -- = 0x00008003

-- | Allocation upper bound written into the control prelude's second
-- 32-bit slot (bytes 4..7 of the EDSIO-serialized control segment,
-- big-endian). Canonical's parser reads this into
-- @source->alloc_total@ at
-- @tools\/xdelta1\/xdelta-1.1.4\/libedsio\/default.c@ and bounds-
-- checks every sub-record allocation against it: a sub-allocation
-- request whose running total would exceed the declared bound fires
-- @EC_EdsioIncorrectAllocation@ and bails. Not a hint — a hard cap.
--
-- The exact "right" value is the in-memory struct allocation
-- canonical would need to reconstruct the parsed objects —
-- platform-dependent (struct layout, pointer size, 8-byte alignment),
-- not derivable from wire bytes alone. Slap doesn't attempt to
-- compute it precisely; this constant is a generous fixed upper
-- bound, large enough to satisfy canonical's check for any patch
-- slap can produce, small enough to fit in a 32-bit word. The cost
-- of over-declaring is wasted-then-freed memory inside canonical's
-- parser, not wire bloat (the field is always 4 bytes regardless of
-- value).
--
-- 16 MiB is comfortably above any realistic per-patch allocation
-- canonical would actually use and well under the 4 GiB ceiling.
-- Revisit if a future patch shape grows past it.
xdelta1ControlAllocationBound :: Word32
xdelta1ControlAllocationBound = 16 * 1024 * 1024
