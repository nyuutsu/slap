-- | The vocabulary a parsed VCDIFF patch decodes into.
--
-- VCDIFF is two flavors over one wire format: RFC 3284 and xdelta3 run the same core and diverge only at named features
-- (@docs\/vcdiff\/core\/spec.md@, @docs\/vcdiff\/partition.md@).
-- The types follow that shape: a flavor sum at the top, a shared 'Window' both flavors fill, per-flavor wrappers only where a flavor adds something.
--
-- Everything here is already decoded:
-- the code table and address cache are decode mechanism, consumed while parsing and gone from the decoded form.
module Slap.VCDIFF.Types
  ( VCDIFFPatch(..)
  , XDelta3Header(..)
  , vcdiffAppHeader
  , vcdiffDeclaredCompressor
  , RFCHeader(..)
  , CustomCodeTable(..)
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
    -- * Indicator bits
  , vcdDecompressBit, vcdCodeTableBit, vcdAppHeaderBit
  , vcdSourceBit, vcdTargetBit, vcdAdler32Bit
  , vcdDataCompBit, vcdInstCompBit, vcdAddrCompBit
    -- * Window sizing (emission)
  , XDelta3WindowSize
  , unXDelta3WindowSize
  , xdelta3WindowSizeOfBytes
  , defaultXDelta3WindowSize
  , xdelta3ReferenceDecoderWindowCap
  ) where

import Slap.Measure (Offset, Length(..), FileSize(..))
import Slap.Checksum (Adler32)
import Slap.VCDIFF.CodeTable (CodeTable)
import Slap.VCDIFF.AddressCache (AddressCacheConfig)
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor)

import Data.Vector (Vector)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)

-- | VCDIFF's identity magic: @D6 C3 C4@, ASCII @VCD@ with the high bit set, opening every patch (docs/vcdiff/core/spec.md "Identity").
-- 'Slap.Detect' matches it to route a patch to the VCDIFF family.
vcdiffMagicBytes :: ByteString
vcdiffMagicBytes = ByteString.pack [0xD6, 0xC3, 0xC4]

----------------------------------------------------------------------------
-- Indicator bits
----------------------------------------------------------------------------

-- The bit positions of the three indicator bitmask bytes.
-- Wire facts the two directions must place identically — 'Slap.VCDIFF.Parse' tests them, 'Slap.VCDIFF.Create' sets them —
-- so, like the magic above, they are named once here.

-- Header indicator (Hdr_Indicator)
vcdDecompressBit, vcdCodeTableBit, vcdAppHeaderBit :: Int
vcdDecompressBit = 0   -- VCD_DECOMPRESS: a secondary compressor is declared
vcdCodeTableBit  = 1   -- VCD_CODETABLE:  a custom code table follows
vcdAppHeaderBit  = 2   -- VCD_APPHEADER:  application data follows

-- Window indicator (Win_Indicator)
vcdSourceBit, vcdTargetBit, vcdAdler32Bit :: Int
vcdSourceBit  = 0   -- VCD_SOURCE:  copies address a segment of the source file
vcdTargetBit  = 1   -- VCD_TARGET:  copies address a segment of produced target
vcdAdler32Bit = 2   -- VCD_ADLER32: a per-window Adler32 follows the section lengths

-- Delta indicator (Delta_Indicator): one bit per section kind,
-- marking that kind's section of this window as a compressed piece of the kind's continuous secondary stream.
vcdDataCompBit, vcdInstCompBit, vcdAddrCompBit :: Int
vcdDataCompBit = 0   -- VCD_DATACOMP: the data section is compressed
vcdInstCompBit = 1   -- VCD_INSTCOMP: the instruction section is compressed
vcdAddrCompBit = 2   -- VCD_ADDRCOMP: the address section is compressed

-- | A parsed VCDIFF patch.
-- An xdelta3 patch can carry an application header and per-window checksums an RFC patch cannot;
-- an RFC patch can carry a custom code table an xdelta3 decoder rejects.
-- 'PatchCoreOnly' uses no flavor-distinguishing feature and decodes identically under either flavor.
data VCDIFFPatch
  = PatchXDelta3  !XDelta3Header !(Vector XDelta3Window)
  | PatchRFC      !RFCHeader     !(Vector Window)
  | PatchCoreOnly                !(Vector Window)
  deriving (Eq, Show)

-- | The xdelta3-only header fields:
-- the optional application header (VCD_APPHEADER, carried once before the windows) and the secondary compressor it declared, if any.
--
-- The compressor's sections are resolved to plain bytes at parse and gone from the decoded form;
-- which compressor was declared is kept, since 'Nothing' here is the difference between a plain xdelta3 patch and a compressed one.
-- The name is a declaration, not a use: a declared compressor no window draws on is a valid state, recorded here all the same.
data XDelta3Header = XDelta3Header
  { xdelta3AppHeader           :: !(Maybe ByteString)
  , xdelta3SecondaryCompressor :: !(Maybe XDelta3SecondaryCompressor)
  }
  deriving (Eq, Show)

-- | The patch's application header (VCD_APPHEADER), present only on an xdelta3 patch.
vcdiffAppHeader :: VCDIFFPatch -> Maybe ByteString
vcdiffAppHeader (PatchXDelta3 header _) = xdelta3AppHeader header
vcdiffAppHeader _                       = Nothing

-- | The patch's declared secondary compressor, present only on an xdelta3 patch.
vcdiffDeclaredCompressor :: VCDIFFPatch -> Maybe XDelta3SecondaryCompressor
vcdiffDeclaredCompressor (PatchXDelta3 header _) = xdelta3SecondaryCompressor header
vcdiffDeclaredCompressor _                       = Nothing

-- | The RFC-only header fields: the optional custom code table (RFC 3284 §7's VCD_CODETABLE) that replaces the default table for this patch.
-- 'Nothing' means the default table is in force.
data RFCHeader = RFCHeader
  { rfcCustomCodeTable :: !(Maybe CustomCodeTable) }
  deriving (Eq, Show)

-- | A patch's custom code table (RFC 3284 §7): the 256 entries the instruction stream indexes,
-- and the address-cache geometry it declares ahead of them, the @s_near@\/@s_same@ pair sizing the near and same caches.
-- The two travel together because the wire ties them (the geometry bytes, then the entries' inner delta)
-- and a window resolves its COPY addresses against the very cache the geometry sizes.
-- A patch on the default table carries no 'CustomCodeTable'; its geometry is then the default four-near\/three-same.
data CustomCodeTable = CustomCodeTable
  { customCodeTableEntries     :: !CodeTable
  , customCodeTableCacheConfig :: !AddressCacheConfig
  }
  deriving (Eq, Show)

-- | A window of an xdelta3 patch:
-- the shared 'Window' plus the optional per-window Adler32 of its decoded output, present exactly when Win_Indicator bit 2 is set.
-- Only xdelta3 windows can carry one, so the wrapper lives here, not on 'Window': an RFC or core-only window bearing a checksum is unrepresentable.
-- The 'Slap.SomePatch' seam lifts each present checksum into @verifyWindowAdler32@.
data XDelta3Window = XDelta3Window
  { xdelta3WindowBody    :: !Window
  , xdelta3WindowAdler32 :: !(Maybe Adler32)
  }
  deriving (Eq, Show)

-- | One window: a self-contained chunk of the target.
-- A patch is a sequence of windows, the target their decoded output concatenated in order.
data Window = Window
  { windowSourceSegment :: !(Maybe SourceSegment)
  , windowTargetSize    :: !FileSize
  , windowInstructions  :: !(Vector VCDIFFInstruction)
  }
  deriving (Eq, Show)

-- | A window's declared target size as the 'Length' its output occupies in the decode buffer.
windowOutputLength :: Window -> Length
windowOutputLength window = Length (unFileSize (windowTargetSize window))

-- | Every window paired with the per-window Adler32 it carries ('Nothing' for a core-only or RFC window, which has no slot for one).
-- The one place the flavor is unfolded; every other view ('patchWindows', the verification lift, the explain walk) is a projection of this one.
patchWindowsWithChecksums :: VCDIFFPatch -> Vector WindowWithChecksum
patchWindowsWithChecksums patch = case patch of
  PatchCoreOnly windows -> fmap withoutChecksum windows
  PatchRFC _ windows    -> fmap withoutChecksum windows
  PatchXDelta3 _ xdelta3Windows -> fmap withChecksum xdelta3Windows
  where
    withoutChecksum window = WindowWithChecksum window Nothing
    withChecksum xdelta3Window =
      WindowWithChecksum (xdelta3WindowBody xdelta3Window) (xdelta3WindowAdler32 xdelta3Window)

-- | A window paired with the per-window Adler32 it carries.
data WindowWithChecksum = WindowWithChecksum
  { windowWithChecksumBody    :: !Window
  , windowWithChecksumAdler32 :: !(Maybe Adler32)
  }
  deriving (Eq, Show)

-- | A patch's windows, flavor-agnostic, the per-window checksums dropped.
patchWindows :: VCDIFFPatch -> Vector Window
patchWindows = fmap windowWithChecksumBody . patchWindowsWithChecksums

-- | One decoded delta instruction. 'Add' carries its literal bytes; 'Run' a length and the byte to repeat;
-- 'Copy' a length and one absolute 'Offset' into the superstring @U = S + T@,
-- the window's source segment @S@ followed by the target @T@ produced so far.
--
-- 'Copy' has a single offset, not a source\/target split:
-- VCDIFF addresses one flat space, where a copy reads from @S@ or from @T@
-- (including the self-referential overlap where the read trails the write, the run-length case) and apply walks it byte by byte through @U@.
-- A copy crossing the segment boundary is malformed (core invariant 2), so the two cases never mix within one copy.
data VCDIFFInstruction
  = Add  !ByteString
  | Run  !Length !Word8
  | Copy !Length !Offset
  deriving (Eq, Show)

-- | The region a window's COPYs address against, when it names one.
data SourceSegment = SourceSegment
  { sourceSegmentOrigin   :: !SegmentOrigin
  , sourceSegmentPosition :: !Offset
  , sourceSegmentLength   :: !Length
  }
  deriving (Eq, Show)

-- | Which side a window's source segment is cut from: the source file (VCD_SOURCE) or the produced target (VCD_TARGET).
-- The spec forbids both bits at once, and neither set means a self-contained window with 'windowSourceSegment' 'Nothing',
-- so this selector exists only where a segment does.
data SegmentOrigin = FromSourceFile | FromProducedTarget
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- Window sizing (emission)
----------------------------------------------------------------------------

-- | The window size an xdelta3 create slices its target by: full-size windows in order, then the remainder,
-- the empty target one empty window (the same emission the canonical tool writes for one).
-- Positive by 'xdelta3WindowSizeOfBytes', the only constructor, so a partition that could not terminate is unrepresentable.
newtype XDelta3WindowSize = XDelta3WindowSize { unXDelta3WindowSize :: Int }
  deriving (Eq, Ord, Show)

-- | The one door to an 'XDelta3WindowSize': any positive byte count. 'Nothing' for zero or less.
xdelta3WindowSizeOfBytes :: Int -> Maybe XDelta3WindowSize
xdelta3WindowSizeOfBytes byteCount
  | byteCount >= 1 = Just (XDelta3WindowSize byteCount)
  | otherwise      = Nothing

-- | 8 MiB: the canonical tool's own encoder default, and comfortably inside what every xdelta3 build decodes.
defaultXDelta3WindowSize :: XDelta3WindowSize
defaultXDelta3WindowSize = XDelta3WindowSize (8 * 1024 * 1024)

-- | 16 MiB: the compiled window ceiling (@XD3_HARDMAXWINSIZE@) of the widespread xdelta3 3.0.11 builds, which refuse to decode a window past it.
-- Later xdelta3 sources raise the ceiling, and other decoders (slap included) have none;
-- a create asked for windows above this is emitting a valid patch that one important decoder will decline,
-- and 'Slap.Convert.createDefaultAdvisories' says so.
xdelta3ReferenceDecoderWindowCap :: XDelta3WindowSize
xdelta3ReferenceDecoderWindowCap = XDelta3WindowSize (16 * 1024 * 1024)
