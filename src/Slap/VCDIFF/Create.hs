{-# LANGUAGE LambdaCase #-}

-- | VCDIFF patch creation: a cover of the target serialized to wire
-- bytes.
--
-- Creation has two halves. A /matcher/ (a later, Rust-backed stage)
-- segments the target into copies and literals — a 'Cover'. This module
-- is the other half: it turns a cover into a VCDIFF patch. It does not
-- find anything; 'createRFCVCDIFF' feeds it the one degenerate cover
-- (the whole target as a single literal), which copies nothing and
-- reproduces the original bedrock floor byte-for-byte, while tests feed
-- it hand-built covers that exercise the full COPY/ADD/RUN path.
--
-- The emitted patch reaches for no flavor-distinguishing feature, so it
-- parses back as 'Slap.VCDIFF.Types.PatchCoreOnly', not @PatchRFC@. That
-- is right, not a gap: the RFC arc's parameterless default genuinely
-- uses only core features (docs/vcdiff/core/spec.md, "A patch that
-- happens to use only the features described here is valid as either
-- flavor"). The @rfc-vcdiff@ token names the arc the user asked for;
-- these bytes happen to be core-shaped because nothing RFC-specific is
-- reached for.
--
-- Instruction selection and the wire layout are uniform and unclever, a
-- floor for a denser encoder to grow on: a literal becomes a 'Run' only
-- when it is a single byte repeated (length ≥ 2), an 'Add' otherwise; a
-- copy passes straight through; every opcode uses the coded-size
-- default-table entry (no inline-size or combined rows) and every COPY
-- address is mode 0 (SELF), the absolute @U@ offset emitted directly
-- with no address cache.
module Slap.VCDIFF.Create
  ( createRFCVCDIFF
    -- * Cover-driven emission (exported for testing)
  , createFromCover
  , coverToInstructions
  ) where

import Slap.VCDIFF.Types (vcdiffMagicBytes, VCDIFFInstruction(..))
import Slap.VCDIFF.Cover (Cover(..), CoverSegment(..))
import Slap.Binary (putVcdiffVarint, viewBytesInRange)
import Slap.Status (SlapError, CreateResult(..))
import Slap.Measure (Offset(..), Length(..), byteLength)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, byteString, word8, toLazyByteString)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Word (Word8)

-- | Create a VCDIFF patch reconstructing @target@. The degenerate cover
-- — the whole target as one literal — copies nothing from the source,
-- so the patch is self-contained and reconstructs the target whatever
-- it is applied against; the 'Either' is shape-symmetry with the other
-- @create*@ entries, whose richer encoders can fail. No metadata, no
-- advisories.
createRFCVCDIFF :: InputFileContents -> OutputFileContents
                -> Either SlapError CreateResult
createRFCVCDIFF inputContents outputContents@(OutputFileContents target) =
  Right (createFromCover inputContents outputContents (wholeTargetCover target))

-- | The degenerate cover: the entire target as a single literal,
-- copying nothing. Run through 'createFromCover' it reproduces the
-- bedrock floor exactly.
wholeTargetCover :: ByteString -> Cover
wholeTargetCover target = Cover [CoverLiteral (Offset 0) (byteLength target)]

-- | Serialize a cover of @target@ against @source@ into a VCDIFF patch.
-- Total: the cover is the contract, and a well-formed cover always
-- serializes — the 'CreateResult' carries no advisories.
createFromCover :: InputFileContents -> OutputFileContents -> Cover -> CreateResult
createFromCover (InputFileContents source) (OutputFileContents target) cover =
  CreateResult (PatchFileContents (emitPatch source target cover)) []

----------------------------------------------------------------------------
-- Cover -> instructions
----------------------------------------------------------------------------

-- | Choose an instruction for each cover segment. A copy passes straight
-- through to 'Copy'. A literal's bytes are sliced from the target and
-- become a 'Run' when they are a single byte repeated (strictly smaller
-- than the equivalent 'Add' once length ≥ 2), an 'Add' otherwise.
coverToInstructions :: ByteString -> Cover -> [VCDIFFInstruction]
coverToInstructions target (Cover segments) = map segmentToInstruction segments
  where
    segmentToInstruction = \case
      CoverCopy copyLength superstringOffset -> Copy copyLength superstringOffset
      CoverLiteral literalStart literalLength ->
        literalToInstruction (viewBytesInRange literalStart literalLength target)

-- | A literal run becomes a 'Run' of its single repeated byte, or an
-- 'Add' of its bytes verbatim.
literalToInstruction :: ByteString -> VCDIFFInstruction
literalToInstruction literalBytes
  | isSingleRepeatedByte literalBytes =
      Run (byteLength literalBytes) (ByteString.head literalBytes)
  | otherwise = Add literalBytes

-- | Whether a run is two or more copies of one byte — the case a 'Run'
-- encodes strictly smaller than an 'Add'. A length-1 (or empty) run is
-- not "repeated" and stays an 'Add', so 'ByteString.head' below it is
-- only reached on a non-empty run.
isSingleRepeatedByte :: ByteString -> Bool
isSingleRepeatedByte bytes =
  byteLength bytes >= Length 2 && ByteString.all (== ByteString.head bytes) bytes

----------------------------------------------------------------------------
-- Cover -> wire
----------------------------------------------------------------------------

-- | The three realized on-wire sections of a window.
data Sections = Sections
  { sectionData         :: !ByteString   -- ^ ADD literals and RUN fill bytes.
  , sectionInstructions :: !ByteString   -- ^ each opcode and its coded size.
  , sectionAddresses    :: !ByteString   -- ^ each COPY's SELF-mode address.
  }

-- | The three section byte-streams under construction. One value is both
-- a single instruction's contribution and — the type being a 'Monoid'
-- that combines the streams componentwise — a whole window's
-- accumulation, so a window's sections are exactly 'foldMap' of its
-- instructions' pieces in order. A field is 'mempty' where an
-- instruction contributes nothing there (a COPY adds no data; an ADD or
-- RUN adds no address).
data SectionBuilders = SectionBuilders
  { dataStream        :: !Builder
  , instructionStream :: !Builder
  , addressStream     :: !Builder
  }

instance Semigroup SectionBuilders where
  SectionBuilders earlierData earlierInstructions earlierAddresses
    <> SectionBuilders laterData laterInstructions laterAddresses =
      SectionBuilders
        (earlierData         <> laterData)
        (earlierInstructions <> laterInstructions)
        (earlierAddresses    <> laterAddresses)

instance Monoid SectionBuilders where
  mempty = SectionBuilders mempty mempty mempty

-- | An instruction's full wire footprint, decided in one place and
-- exhaustive over the three kinds — no wildcard, so a fourth kind could
-- not slip through silently. Reading one arm shows everything an
-- instruction emits and which stream it lands in.
wirePieces :: VCDIFFInstruction -> SectionBuilders
wirePieces = \case
  Add literal -> SectionBuilders
    { dataStream        = byteString literal
    , instructionStream = word8 addOpcodeSizeCoded <> varintOfLength (byteLength literal)
    , addressStream     = mempty }
  Run runLength fillByte -> SectionBuilders
    { dataStream        = word8 fillByte
    , instructionStream = word8 runOpcodeSizeCoded <> varintOfLength runLength
    , addressStream     = mempty }
  Copy copyLength address -> SectionBuilders
    { dataStream        = mempty
    , instructionStream = word8 copyOpcodeMode0SizeCoded <> varintOfLength copyLength
    , addressStream     = varintOfOffset address }

-- | Collect a window's instructions into the three realized sections:
-- fold every instruction's pieces together, then render each stream to
-- bytes. Section bytes are the ordered concatenation of the
-- per-instruction contributions, the fold being a monoid homomorphism.
layoutSections :: [VCDIFFInstruction] -> Sections
layoutSections instructions = Sections
  { sectionData         = builderBytes (dataStream combined)
  , sectionInstructions = builderBytes (instructionStream combined)
  , sectionAddresses    = builderBytes (addressStream combined)
  }
  where
    combined = foldMap wirePieces instructions

-- | Whether a window's instructions read from the superstring — i.e.
-- contain a COPY. A copying window declares its source segment; an
-- all-literal one is self-contained. Total over the three kinds.
hasCopy :: [VCDIFFInstruction] -> Bool
hasCopy = any $ \case
  Copy _ _ -> True
  Add _    -> False
  Run _ _  -> False

-- | Serialize a whole patch: the fixed header, then one window holding
-- the cover's instructions. When any instruction copies, the window
-- declares the entire source as its segment (so the COPY addresses can
-- reach into @U@); otherwise the window is self-contained and the two
-- segment varints are absent, reproducing the bedrock floor exactly.
emitPatch :: ByteString -> ByteString -> Cover -> ByteString
emitPatch source target cover = builderBytes
  (  byteString vcdiffMagicBytes
  <> word8 version0
  <> word8 noHeaderFeatures
  <> windowBuilder )
  where
    instructions = coverToInstructions target cover
    sections     = layoutSections instructions

    -- The Win_Indicator and (when copying) the source-segment varints,
    -- which precede the delta-encoding-length on the wire.
    windowIndicatorAndSegment
      | hasCopy instructions =
             word8 sourceSegmentWindow
          <> varintOfLength (byteLength source)   -- source-segment length
          <> putVcdiffVarint 0                    -- source-segment position
      | otherwise = word8 selfContainedWindow

    -- Everything the delta-encoding-length field measures: the target
    -- window size, the indicator, the three section lengths, then the
    -- three sections in order.
    deltaEncoding = builderBytes
      (  varintOfLength (byteLength target)
      <> word8 noSectionsCompressed
      <> varintOfLength (byteLength (sectionData sections))
      <> varintOfLength (byteLength (sectionInstructions sections))
      <> varintOfLength (byteLength (sectionAddresses sections))
      <> byteString (sectionData sections)
      <> byteString (sectionInstructions sections)
      <> byteString (sectionAddresses sections) )

    windowBuilder =
         windowIndicatorAndSegment
      <> varintOfLength (byteLength deltaEncoding)
      <> byteString deltaEncoding

----------------------------------------------------------------------------
-- Varint helpers and named wire constants
----------------------------------------------------------------------------

-- | A 'Length' as a VCDIFF varint.
varintOfLength :: Length -> Builder
varintOfLength (Length n) = putVcdiffVarint (fromIntegral n)

-- | An 'Offset' as a VCDIFF varint — a COPY's absolute @U@ address.
varintOfOffset :: Offset -> Builder
varintOfOffset (Offset n) = putVcdiffVarint (fromIntegral n)

-- | Default code-table index 1: ADD with its size coded separately
-- (RFC 3284 §5.6).
addOpcodeSizeCoded :: Word8
addOpcodeSizeCoded = 0x01

-- | Default code-table index 0: RUN with its size coded separately
-- (RFC 3284 §5.6).
runOpcodeSizeCoded :: Word8
runOpcodeSizeCoded = 0x00

-- | Default code-table index 19: COPY in mode 0 (SELF) with its size
-- coded separately (RFC 3284 §5.6). Mode 0 means the address is a plain
-- varint, no cache slot consulted.
copyOpcodeMode0SizeCoded :: Word8
copyOpcodeMode0SizeCoded = 0x13

-- | Version byte: VCDIFF is at version 0 (RFC 3284 §4.1).
version0 :: Word8
version0 = 0x00

-- | Hdr_Indicator with no bits set: no secondary compressor, no custom
-- code table, no application header.
noHeaderFeatures :: Word8
noHeaderFeatures = 0x00

-- | Win_Indicator with no bits set: a self-contained window, no source
-- segment, so its two source-segment varints are absent.
selfContainedWindow :: Word8
selfContainedWindow = 0x00

-- | Win_Indicator with the VCD_SOURCE bit set: the window's COPYs may
-- address a segment of the source file, named by the two varints that
-- follow.
sourceSegmentWindow :: Word8
sourceSegmentWindow = 0x01

-- | Delta_Indicator with no bits set: none of the three sections is
-- secondary-compressed.
noSectionsCompressed :: Word8
noSectionsCompressed = 0x00

-- | Render a 'Builder' to a strict 'ByteString'.
builderBytes :: Builder -> ByteString
builderBytes = LazyByteString.toStrict . toLazyByteString
