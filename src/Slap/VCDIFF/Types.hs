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
  , windowOutputLength
  , patchWindows
  , patchWindowsWithChecksums
  , WindowWithChecksum(..)
  , VCDIFFInstruction(..)
  , SourceSegment(..)
  , SegmentOrigin(..)
  , vcdiffMagicBytes
  ) where

import Slap.Measure (Offset, Length(..), FileSize(..))
import Slap.Checksum (Adler32)
import Slap.VCDIFF.CodeTable (CodeTable)
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor)

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

-- | The xdelta3-only header fields: the optional application header
-- (the VCD_APPHEADER data an xdelta3 patch may carry once, before its
-- windows), and the secondary compressor it declared, if any.
--
-- The compressor's /sections/ are decode mechanism — resolved to plain
-- bytes during parse, gone from the decoded form like the code table
-- and the address cache. But /which/ compressor was declared is a fact
-- about the patch worth keeping: it is the only registry a compressor
-- id belongs to, it is part of how the patch describes itself, and a
-- 'Nothing' here ('Just' there) is the difference between a plain
-- xdelta3 patch and a compressed one. So the name survives even when
-- the bytes it governed do not. A declared compressor that no window
-- ever draws on is a real, valid state — it is still recorded here, as
-- a declaration, not a use.
data XDelta3Header = XDelta3Header
  { xdelta3AppHeader           :: !(Maybe ByteString)
  , xdelta3SecondaryCompressor :: !(Maybe XDelta3SecondaryCompressor)
  }
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

-- | A window's declared target size, as the 'Length' its output
-- occupies in the buffer it is decoded into. The shared projection
-- behind both the apply walk (placing each window's output) and the
-- verification lift (sizing each window's checksum range).
windowOutputLength :: Window -> Length
windowOutputLength window = Length (unFileSize (windowTargetSize window))

-- | Every window of a patch paired with the per-window Adler32 it
-- carries — 'Nothing' for a core-only or RFC window, neither of which
-- has a slot for one. The one place the flavor is unfolded: a patch's
-- windows differ across flavors only in whether a checksum rides with
-- each, so this is the maximal-information flattening, and every other
-- view of "this patch's windows" ('patchWindows', the verification
-- lift, the explain walk) is a projection of it. Exhaustive over the
-- three flavors, no wildcard.
patchWindowsWithChecksums :: VCDIFFPatch -> Vector WindowWithChecksum
patchWindowsWithChecksums patch = case patch of
  PatchCoreOnly windows -> fmap withoutChecksum windows
  PatchRFC _ windows    -> fmap withoutChecksum windows
  PatchXDelta3 _ xdelta3Windows -> fmap withChecksum xdelta3Windows
  where
    withoutChecksum window = WindowWithChecksum window Nothing
    withChecksum xdelta3Window =
      WindowWithChecksum (xdelta3WindowBody xdelta3Window) (xdelta3WindowAdler32 xdelta3Window)

-- | A window paired with the per-window Adler32 it carries — 'Nothing'
-- for a core-only or RFC window, which has no slot for one. The
-- flavor-flattened unit 'patchWindowsWithChecksums' yields; the
-- verification lift and the explain walk read its fields by name rather
-- than by tuple position. Mirrors 'XDelta3Window' in shape, but
-- flavor-agnostic — the checksum is optional because two of the three
-- flavors never carry one.
data WindowWithChecksum = WindowWithChecksum
  { windowWithChecksumBody    :: !Window
  , windowWithChecksumAdler32 :: !(Maybe Adler32)
  }
  deriving (Eq, Show)

-- | The windows of a patch, flavor-agnostic, with the per-window
-- checksums dropped. A projection of 'patchWindowsWithChecksums', so the
-- flavor unfolds in exactly one place.
patchWindows :: VCDIFFPatch -> Vector Window
patchWindows = fmap windowWithChecksumBody . patchWindowsWithChecksums

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
