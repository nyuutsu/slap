{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | The VCDIFF wing of the status vocabulary.
module Slap.Status.VCDIFF
  ( VCDIFFShapeViolation(..)
  , VCDIFFCodeTableMalformation(..)
  , VCDIFFCodeTableField(..)
  , codeTableFieldName
  , VCDIFFCodeTableTemplateKind(..)
  , codeTableTemplateKindPhrase
  , VCDIFFRFCFeature(..)
  , VCDIFFXDelta3Feature(..)
  , VCDIFFMalformation(..)
  , VCDIFFIndicatorKind(..)
  , indicatorKindName
  , ReservedBitsSet(..)
  , VCDIFFSection(..)
  , vcdiffSectionName
  , VCDIFFOnDemandSection(..)
  ) where

import Slap.Binary (VarintReadFailure)
import Slap.JSON.Nullary (AsConstructorName(..))
import Slap.Measure (Length, ActionIndex, ActualOffset,
                     ExpectedSize, ActualSize, ActualLength)
import Slap.Status.Vocabulary (CompressionAlgorithm)

import Data.Aeson (ToJSON)
import Data.Text (Text)
import Data.Word (Word8)
import GHC.Generics (Generic, Generically(..))

-- | The one off-spec wire shape 'Slap.Status.UnsupportedVCDIFFShape' carries: a custom code table's inner delta declaring a custom table of its own.
-- RFC 3284 §7c requires the inner delta to use the default table; 'Slap.VCDIFF.Parse' decodes it with custom tables forbidden,
-- so the refusal points at the header's table declaration, not the inner body.
data VCDIFFShapeViolation
  = VCDIFFNestedCustomCodeTable
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via AsConstructorName VCDIFFShapeViolation

-- | The structural failures of decoding a VCDIFF custom code table, validated outside the byte parser.
-- Most are decidable from the 1536-byte image alone and surface from 'Slap.VCDIFF.CodeTable.deserializeCodeTable';
-- 'VCDIFFCodeTableHeaderTooShort' fails before the image exists, and 'VCDIFFCodeTableCopyModeOutOfRange' after it,
-- against the declared cache sizes — both in 'Slap.VCDIFF.Parse'.
data VCDIFFCodeTableMalformation
  -- | The serialized code-table bytes are not the spec-mandated 1536-byte width (six 256-entry slices).
  = VCDIFFCodeTableWrongLength !ActualLength
  -- | A byte in a types slice outside the valid instruction type tags (Noop=0, Add=1, Run=2, Copy=3).
  | VCDIFFCodeTableInvalidInstructionType !Word8
  -- | The custom-code-table data section is shorter than the 2-byte header (near-cache size, same-cache size) it must begin with.
  | VCDIFFCodeTableHeaderTooShort
  -- | A size or mode byte was nonzero for a template type that carries no such field.
  -- The grammar gives those bytes exactly one well-formed value (zero, matching the default-table image a custom image is delta-encoded against),
  -- so a nonzero value is not an alternative spelling of anything: it is evidence the table bytes are damaged,
  -- and with no checksum in this arc the table check is the tripwire (docs/vcdiff/rfc-vcdiff/questions.md, "invalid decoded-table entries").
  | VCDIFFCodeTableUnusedFieldSet !VCDIFFCodeTableTemplateKind !VCDIFFCodeTableField !Word8
  -- | A COPY template named an address mode the declared caches do not reach: at or above @2 + s_near + s_same@,
  -- the band 'Slap.VCDIFF.Parse.classifyAddressMode' admits. Checked once at table-build, used or not —
  -- damage evidence on the same reasoning as 'VCDIFFCodeTableUnusedFieldSet'.
  | VCDIFFCodeTableCopyModeOutOfRange !Word8 !Word8
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VCDIFFCodeTableMalformation

-- | Which per-template byte of the serialized code-table image a malformation names: the size byte or the mode byte.
data VCDIFFCodeTableField = CodeTableSizeField | CodeTableModeField
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VCDIFFCodeTableField

codeTableFieldName :: VCDIFFCodeTableField -> Text
codeTableFieldName CodeTableSizeField = "size"
codeTableFieldName CodeTableModeField = "mode"

-- | The instruction type of the template whose unused byte held a value.
-- COPY has no place here: its templates carry both a size and a mode, so neither byte is ever unused.
data VCDIFFCodeTableTemplateKind = CodeTableNoopTemplate | CodeTableAddTemplate | CodeTableRunTemplate
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VCDIFFCodeTableTemplateKind

-- | The template kind as the message speaks of it, article included.
codeTableTemplateKindPhrase :: VCDIFFCodeTableTemplateKind -> Text
codeTableTemplateKindPhrase CodeTableNoopTemplate = "a no-op"
codeTableTemplateKindPhrase CodeTableAddTemplate  = "an ADD"
codeTableTemplateKindPhrase CodeTableRunTemplate  = "a RUN"

-- | The two RFC 3284 features xdelta3 refuses — the RFC half of 'Slap.Status.VCDIFFRFCFeatureWithXDelta3Feature'.
data VCDIFFRFCFeature
  = RFCFeatureTargetWindow    -- ^ Win_Indicator VCD_TARGET: a window copying earlier target output.
  | RFCFeatureCustomCodeTable -- ^ Hdr_Indicator VCD_CODETABLE: a custom code table.
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VCDIFFRFCFeature

-- | The xdelta3-extension half of 'Slap.Status.VCDIFFRFCFeatureWithXDelta3Feature'.
-- When a patch carries several, the classifier reports whichever it met first: compressor, then header, then checksum.
data VCDIFFXDelta3Feature
  = XDelta3FeatureSecondaryCompressor  -- ^ a declared secondary compressor (VCD_DECOMPRESS).
  | XDelta3FeatureApplicationHeader    -- ^ an application header (VCD_APPHEADER).
  | XDelta3FeatureWindowChecksum       -- ^ a per-window Adler32 (VCD_ADLER32).
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VCDIFFXDelta3Feature

-- | A semantics failure in a VCDIFF patch that parsed at the byte level, carried by 'Slap.Status.MalformedVCDIFF' —
-- the loud refusals the core invariants demand (docs/vcdiff/core/spec.md "Core invariants").
-- Every arm is a claim slap understands and finds invalid; the claims it cannot interpret decline instead,
-- through 'Slap.Status.VCDIFFReservedIndicatorBits' and 'Slap.Status.VCDIFFUnknownSecondaryCompressor'.
-- The 'ActionIndex' an arm carries counts decoded instructions, not instruction-section bytes:
-- one code byte can carry two instructions, and an inline size varint widens others,
-- so the index names what the stream means rather than where it sits.
data VCDIFFMalformation
  -- | A window's indicator set both VCD_SOURCE and VCD_TARGET, which RFC 3284 §4.2 forbids.
  = VCDIFFBothSourceAndTargetWindowBits
  -- | Core invariant 1's upper edge: a COPY address at or past the current write position, naming bytes no instruction has produced yet.
  | VCDIFFCopyReadsUnwrittenOutput !ActionIndex
  -- | Core invariant 1's lower edge: a COPY address decoded below zero.
  -- Only the HERE mode can land there — its address is a subtraction from the write position.
  | VCDIFFCopyAddressNegative !ActionIndex !ActualOffset
  -- | Core invariant 2: a COPY that begins inside the source segment must not run past its end.
  | VCDIFFCopyCrossesSourceSegmentEnd !ActionIndex
  -- | Core invariant 3: a window's instructions must produce exactly its declared target size ('ExpectedSize' declared, 'ActualSize' produced).
  | VCDIFFWindowSizeMismatch !ExpectedSize !ActualSize
  -- | An instruction demanded more bytes than its 'VCDIFFSection' holds — the data, instruction, or address section ran short.
  | VCDIFFSectionExhausted !VCDIFFSection !ActionIndex
  -- | A COPY named an address mode past the highest one the cache configuration defines (the mode as read, then that highest mode) —
  -- the mid-decode sibling of 'VCDIFFCodeTableCopyModeOutOfRange', which catches the same excess at table-build.
  | VCDIFFInvalidCopyAddressMode !ActionIndex !Word8 !Word8
  -- | A window's declared delta-encoding length disagrees with the measured span of its own fields.
  -- A self-consistency check the core ruling demands, not a boundary slap navigates by:
  -- a mismatch catches corruption (docs/vcdiff/core/questions.md, "delta-encoding-length"). The 'ExpectedSize' is the wire declaration;
  -- the 'ActualSize' is the span the framer measured.
  | VCDIFFDeltaEncodingLengthMismatch !ExpectedSize !ActualSize
  -- | A window's instructions finished with a section's declared 'ExpectedSize' not fully consumed: the leftover 'Length' nothing read.
  -- The window declared section lengths its own instructions contradict —
  -- the sibling of 'VCDIFFDeltaEncodingLengthMismatch' (docs/vcdiff/core/questions.md, "leftover bytes").
  | VCDIFFSectionUnconsumedBytes !VCDIFFOnDemandSection !ExpectedSize !Length
  -- | A section flagged secondary-compressed whose bytes cannot supply the decompressed-size varint every compressed section begins with.
  -- Rejected per docs/vcdiff/xdelta3/questions.md, "compressed-but-empty section".
  | VCDIFFCompressedSectionWithoutDeclaredSize !VCDIFFSection !VarintReadFailure
  -- | A section flagged secondary-compressed whose decompressed-size varint is zero.
  -- A category error rather than a no-op: compressing nothing yields framing bytes, never zero bytes, so a section cannot decompress to empty.
  -- xd3 rejects it as "invalid output size"; slap does too.
  | VCDIFFCompressedSectionDeclaresEmptyOutput !VCDIFFSection
  -- | A window's Delta_Indicator flags a section as compressed, but the patch's header declares no secondary compressor.
  -- The two declarations live in the same patch and contradict each other; there is no algorithm the section could be decoded by.
  | VCDIFFCompressedSectionWithoutCompressor !VCDIFFSection
  -- | A secondary stream finished decoding with input left over: the named 'Length' of it.
  -- Mirrors xd3's "finished with unused input" verdict (@xd3_decode_secondary@),
  -- kept distinct from the short-output sibling below because over-supplied input and under-produced output are different faults.
  -- The 'CompressionAlgorithm' names the decoder that was running, and fixes the stream's granularity:
  -- a windows-spanning gathered stream for LZMA, one section's own self-contained stream for DJW.
  | VCDIFFSecondaryStreamUnconsumedInput !VCDIFFSection !CompressionAlgorithm !Length
  -- | A secondary stream decoded to a byte count other than its framing declared. Mirrors xd3's "short output" verdict;
  -- the 'ExpectedSize' is the declared size (the sections' sum for LZMA's gathered kind, the one section's own for DJW),
  -- the 'ActualSize' what the decoder produced.
  | VCDIFFSecondaryStreamOutputSizeMismatch !VCDIFFSection !CompressionAlgorithm !ExpectedSize !ActualSize
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VCDIFFMalformation

-- | Which of a VCDIFF patch's three indicator bytes carried a reserved bit, for 'Slap.Status.VCDIFFReservedIndicatorBits'.
data VCDIFFIndicatorKind = HeaderIndicator | WindowIndicator | DeltaIndicator
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VCDIFFIndicatorKind

-- | An indicator byte's set reserved bits, masked free of the defined ones, for 'Slap.Status.VCDIFFReservedIndicatorBits'.
newtype ReservedBitsSet = ReservedBitsSet Word8
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | One of a VCDIFF window's three data sections — and, since sections of one kind form a continuous secondary stream across windows,
-- also the name of that kind in the secondary-compression arms above.
data VCDIFFSection = VCDIFFDataSection | VCDIFFInstructionSection | VCDIFFAddressSection
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VCDIFFSection

-- | The two sections instructions pull from on demand, and so the two a finished walk can leave unconsumed.
-- The instruction section has no place here: it drives the walk, which ends exactly when it is spent.
data VCDIFFOnDemandSection = OnDemandDataSection | OnDemandAddressSection
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VCDIFFOnDemandSection

indicatorKindName :: VCDIFFIndicatorKind -> Text
indicatorKindName HeaderIndicator = "header indicator"
indicatorKindName WindowIndicator = "window indicator"
indicatorKindName DeltaIndicator  = "delta indicator"

vcdiffSectionName :: VCDIFFSection -> Text
vcdiffSectionName VCDIFFDataSection        = "data"
vcdiffSectionName VCDIFFInstructionSection = "instruction"
vcdiffSectionName VCDIFFAddressSection     = "address"
