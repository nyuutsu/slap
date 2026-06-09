-- | The vocabulary a parsed VCDIFF patch decodes into.
--
-- VCDIFF is two flavors over one shared substrate: RFC 3284 and
-- xdelta3 execute the same core wire format and diverge only at named
-- features (@docs\/vcdiff\/core\/spec.md@, @docs\/vcdiff\/partition.md@).
-- These types follow that shape — a flavor sum at the top, a shared
-- 'Window' both flavors fill, and per-flavor wrappers only where a
-- flavor genuinely adds something the others cannot carry.
--
-- Everything here is already decoded. The code table and address cache
-- are decode mechanism, consumed while parsing; they do not appear in
-- the decoded form, exactly as BPS's varints and CRCs do not survive
-- into 'Slap.BPS.Types.BPSAction'.
module Slap.VCDIFF.Types
  ( VCDIFFPatch(..)
  , XDelta3Header(..)
  , RFCHeader(..)
  , XDelta3Window(..)
  , Window(..)
  , VCDIFFInstruction(..)
  , SourceSegment(..)
  , SegmentOrigin(..)
  , vcdiffMagicBytes
  ) where

import Slap.Measure (Offset, Length, FileSize)
import Slap.Checksum (Adler32)
import Slap.VCDIFF.CodeTable (CodeTable)

import Data.Vector (Vector)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)

-- | VCDIFF's identity magic: the three bytes @D6 C3 C4@ (ASCII @V@ @C@
-- @D@ with the high bit set), at the very start of every patch
-- (docs/vcdiff/core/spec.md "Identity"). 'Slap.Detect' matches on it
-- to route a patch to the VCDIFF family.
vcdiffMagicBytes :: ByteString
vcdiffMagicBytes = ByteString.pack [0xD6, 0xC3, 0xC4]

-- | A parsed VCDIFF patch, named for which of the three things it
-- honestly is. The flavor is not a styling choice layered over one
-- representation: an xdelta3 patch can carry an application header and
-- per-window checksums an RFC patch cannot, and an RFC patch can carry
-- a custom code table an xdelta3 decoder rejects. 'PatchCoreOnly' is a
-- first-class verdict — a patch that uses no flavor-distinguishing
-- feature, decoding identically under either flavor — not a silent
-- lean toward one side. Modeling all three keeps the question "which
-- flavor is this" answered by the constructor rather than by inspecting
-- fields after the fact.
data VCDIFFPatch
  = PatchXDelta3  !XDelta3Header !(Vector XDelta3Window)
  | PatchRFC      !RFCHeader     !(Vector Window)
  | PatchCoreOnly                !(Vector Window)
  deriving (Eq, Show)

-- | The xdelta3-only header fields. Today just the optional
-- application header (the VCD_APPHEADER data an xdelta3 patch may carry
-- once, before its windows); secondary compression and the version /
-- indicator-bit handling arrive in later prompts.
data XDelta3Header = XDelta3Header
  { xdelta3AppHeader :: !(Maybe ByteString) }
  deriving (Eq, Show)

-- | The RFC-only header fields. Today just the optional custom code
-- table (RFC 3284 §7's VCD_CODETABLE) that replaces the default table
-- for this patch; 'Nothing' means the default table is in force.
data RFCHeader = RFCHeader
  { rfcCustomCodeTable :: !(Maybe CodeTable) }
  deriving (Eq, Show)

-- | A window of an xdelta3 patch: the shared 'Window' plus the
-- optional per-window Adler32 of that window's decoded output. The
-- checksum is per-window and optional (it is present exactly when
-- Win_Indicator bit 2 is set), and only xdelta3 windows can carry it —
-- so the wrapper lives here and not on 'Window'. An RFC or core-only
-- window bearing a checksum is therefore unrepresentable. (The
-- 'Slap.SomePatch' seam later lifts each present checksum into
-- @verifyWindowAdler32@, the way the BPS seam lifts @bpsTargetCRC@ into
-- @verifyTargetCRC32@.)
data XDelta3Window = XDelta3Window
  { xdelta3WindowBody    :: !Window
  , xdelta3WindowAdler32 :: !(Maybe Adler32)
  }
  deriving (Eq, Show)

-- | One window: a self-contained chunk of the target. A patch is a
-- sequence of windows, and the target is their decoded output
-- concatenated in order. The instructions are held already decoded
-- ('Vector' 'VCDIFFInstruction') because VCDIFF parse is source-free
-- and decodes eagerly, the same way BPS parses into a 'Vector' of
-- 'Slap.BPS.Types.BPSAction'.
data Window = Window
  { windowSourceSegment :: !(Maybe SourceSegment)
  , windowTargetSize    :: !FileSize
  , windowInstructions  :: !(Vector VCDIFFInstruction)
  }
  deriving (Eq, Show)

-- | One decoded delta instruction. 'Add' carries its literal bytes;
-- 'Run' carries a length and the single byte to repeat; 'Copy' carries
-- a length and one absolute 'Offset' into the superstring @U = S + T@
-- (the window's source segment @S@ followed by the target @T@ produced
-- so far).
--
-- 'Copy' has a single offset, not a source\/target split — unlike
-- BPS's two copy opcodes. VCDIFF addresses one flat space: a copy
-- reads either from the source segment or from the produced target
-- (the latter including the self-referential overlap where the read
-- trails the write, the run-length case), and apply reads it byte by
-- byte through @U@. A copy that crosses the segment boundary is
-- malformed (core invariant 2), so the two cases never mix within one
-- copy. The address mode and cache that compactly encoded that offset
-- on the wire are encoding detail, discarded at decode; the decoded
-- absolute offset is the fact that remains.
data VCDIFFInstruction
  = Add  !ByteString
  | Run  !Length !Word8
  | Copy !Length !Offset
  deriving (Eq, Show)

-- | The region a window's COPY instructions address against, when the
-- window names one. Its 'sourceSegmentOrigin' says whether the region
-- is taken from the source file or from the target produced so far;
-- 'sourceSegmentPosition' and 'sourceSegmentLength' locate it within
-- that origin.
data SourceSegment = SourceSegment
  { sourceSegmentOrigin   :: !SegmentOrigin
  , sourceSegmentPosition :: !Offset
  , sourceSegmentLength   :: !Length
  }
  deriving (Eq, Show)

-- | Which side a window's source segment is cut from: the source file
-- (VCD_SOURCE) or the target produced so far (VCD_TARGET). The spec
-- forbids both bits at once; when neither is set the window is
-- self-contained and 'windowSourceSegment' is 'Nothing', so this
-- selector only exists where a segment actually does.
data SegmentOrigin = FromSourceFile | FromProducedTarget
  deriving (Eq, Show)
