module Slap.IPS.Types
  ( IPSVariant(..)
  , OffsetWidth(..)
  , offsetWidthByteCount
  , IPSVariantSpec(..)
  , IPSRecord(..)
  , ipsRecordOffset
  , recordPayloadLength
  , IPSPatch(..)
  , EBPMetadata(..)
  , emptyEBPMetadata
  , EBPPatch(..)
  , IPSParseResult(..)
  , SMCShapeRequirement(..)
  , isSMCShapedSize
    -- * Truncation-marker disposition
  , MarkerDisposition(..)
  , decideMarkerDisposition
  , effectiveTargetSize
    -- * Named constants
  , ipsMagicBytes
  , ips32MagicBytes
  , ipsEOFMarkerBytes
  , ips32EEOFMarkerBytes
  , ipsMagicLength
  , ipsEOFMarkerLength
  , ips32EEOFMarkerLength
  , ipsRecordSizeFieldLength
  , ipsRecordHeaderLength
  , ipsCopyRecordOverhead
  , ipsRleCountFieldLength
  , ipsRleFillByteLength
  , ipsRleRecordOverhead
  , ipsMaxRecordPayload
    -- * Per-variant dispatch
  , variantSpec
  , ipsVariantMaxRecordEnd
    -- * Encoding limits
  , ipsLimits
  , ips32Limits
  , ebpLimits
    -- * Source/target size-pair rules
  , ipsRejectIncompatibleSizeChange
  , ips32RejectIncompatibleSizeChange
  , ebpRejectIncompatibleSizeChange
  ) where

import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as ByteString8
import Data.Vector (Vector)
import Data.Word (Word8)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Narrow (EncodingLimits(..))
import Slap.Status (SlapError(..), UnencodeabilityReason(..))
import Slap.Text (EncodedText)
import Slap.Measure
  ( Offset(..)
  , Length(..)
  , FileSize(..)
  , Cursor(..)
  , DeclaredTargetSize(..)
  , NaturalTargetSize(..)
  , ActualSize(..)
  , ExpectedSize(..)
  , MaxOffset(..)
  , byteLength
  , fileSizeToInt
  , offsetToInt
  , ipsSentinel
  , ips32Sentinel
  )

-- | Which IPS variant a patch belongs to. The two variants are
-- wire-level distinct: 'StandardIPS' uses @PATCH@/@EOF@ framing with
-- 24-bit record offsets, while 'IPS32' uses @IPS32@/@EEOF@ framing
-- with 32-bit record offsets. EBP is not a distinct variant at this
-- layer — structurally, an EBP patch is a 'StandardIPS' patch with
-- a trailing JSON metadata blob, modeled as 'EBPPatch' wrapping an
-- 'IPSPatch'.
data IPSVariant
  = StandardIPS
  | IPS32
  deriving (Show, Eq)

-- | The width of the offset field in an IPS record, in bytes. The
-- 'StandardIPS' wire format packs record offsets into three bytes
-- (24-bit, big-endian); 'IPS32' widens this to four bytes (32-bit,
-- big-endian). Everywhere that would otherwise thread a bare @Int@
-- width parameter threads an 'OffsetWidth' instead, so nothing
-- outside this module pattern-matches on the raw @3@/@4@.
data OffsetWidth
  = Offset24
  | Offset32
  deriving (Show, Eq)

-- | The one place the 3/4 mapping lives; callers receive a 'Length' and never touch the raw integer.
offsetWidthByteCount :: OffsetWidth -> Length
offsetWidthByteCount Offset24 = Length 3
offsetWidthByteCount Offset32 = Length 4

-- | Per-variant wire facts collected in a single record. The one
-- place in the codebase that knows how 'StandardIPS' and 'IPS32'
-- differ at the wire level: the magic bytes that head a patch, the
-- offset width used by every record, the trailer bytes that close
-- the record stream, the offset value whose big-endian encoding
-- collides with that trailer (used by the sentinel-avoidance pass
-- at encode time), and the maximum offset any single record can
-- name. Parse and Create consume this record instead of hardcoding
-- their own copies of the same facts.
data IPSVariantSpec = IPSVariantSpec
  { ipsVariantMagic                :: !ByteString
    -- ^ Magic bytes that appear at the very start of a patch of this
    -- variant: @"PATCH"@ for 'StandardIPS', @"IPS32"@ for 'IPS32'.
    -- Both happen to be five bytes long; the equality is not
    -- load-bearing.
  , ipsVariantOffsetWidth          :: !OffsetWidth
    -- ^ Width of the offset field in every record of this variant.
  , ipsVariantEOFMarker            :: !ByteString
    -- ^ Trailer bytes that close the record stream: @"EOF"@ for
    -- 'StandardIPS' (three bytes), @"EEOF"@ for 'IPS32' (four bytes).
  , ipsVariantSentinel             :: !Offset
    -- ^ The offset value whose big-endian encoding collides with
    -- 'ipsVariantEOFMarker'. Any record emitted with this exact
    -- offset would be indistinguishable from the trailer on parse,
    -- so the encoder's sentinel-avoidance pass rejects or rewrites
    -- any record whose offset equals it.
  , ipsVariantMaxAddressableOffset :: !Offset
    -- ^ The largest offset a single record can name in this variant:
    -- @0xFFFFFF@ for 'StandardIPS' (24-bit cap), @0xFFFFFFFF@ for
    -- 'IPS32' (32-bit cap). A record offset above this value cannot
    -- be encoded.
  } deriving (Show)

-- | A single IPS record. 'StandardIPS', 'IPS32', and EBP all share
-- this record shape — the variant distinction lives in
-- 'IPSVariantSpec', not here. Two constructors:
--
--   * 'IPSRecordCopy' carries a literal payload that is written
--     verbatim to the target beginning at its offset.
--
--   * 'IPSRecordRLE' carries a run length and a fill byte, and
--     expands at apply time into @ipsRleCount@ copies of
--     @ipsRleFill@ written beginning at its offset. On the wire,
--     this is the record whose size field is zero (used as a
--     sentinel), followed by the run length and fill byte.
data IPSRecord
  = IPSRecordCopy
      { ipsCopyOffset  :: !Offset
      , ipsCopyPayload :: !ByteString
      }
  | IPSRecordRLE
      { ipsRleOffset :: !Offset
      , ipsRleCount  :: !Length
      , ipsRleFill   :: !Word8
      }
  deriving (Show)

-- | The target offset at which an 'IPSRecord' applies, regardless of
-- whether the record is a copy or an RLE run. Exists so Describe
-- and Apply can talk about record offsets in constructor-agnostic
-- code without pattern-matching at every site.
ipsRecordOffset :: IPSRecord -> Offset
ipsRecordOffset (IPSRecordCopy { ipsCopyOffset = offset }) = offset
ipsRecordOffset (IPSRecordRLE  { ipsRleOffset  = offset }) = offset

-- | The number of bytes a single 'IPSRecord' writes to the target when applied:
-- the payload length for a copy record, the run length for an RLE record.
-- Lives here for the same reason as 'ipsRecordOffset': variant-agnostic code in 'Slap.IPS.Parse' and 'Slap.IPS.Apply' reads it without pattern-matching per site.
recordPayloadLength :: IPSRecord -> Length
recordPayloadLength IPSRecordCopy { ipsCopyPayload = payload   } = byteLength payload
recordPayloadLength IPSRecordRLE  { ipsRleCount    = runLength } = runLength

-- | A parsed IPS-family patch, independent of whether the on-wire
-- form was 'StandardIPS' or 'IPS32'. EBP is not represented here:
-- 'StandardIPS' patches that arrived inside an EBP wrapper are
-- stored as 'IPSPatch' values held inside an 'EBPPatch'.
data IPSPatch = IPSPatch
  { ipsVariant             :: !IPSVariant
    -- ^ The wire variant this patch was parsed from or will be
    -- emitted as.
  -- | Record stream as a boxed 'Vector'. Boxed (not unboxed or
  -- storable) because 'IPSRecord' is a sum type containing a
  -- 'ByteString'. Stored as a 'Vector' rather than a list for the same
  -- reason BPS stores its action stream as one: IPS32's 32-bit offset
  -- space admits enough records that a single contiguous array of
  -- pointers is kinder to the GC during apply than millions of
  -- individually allocated cons cells.
  , ipsRecords             :: !(Vector IPSRecord)
  , ipsTruncatedTargetSize :: !(Maybe FileSize)
    -- ^ The target file size declared by a post-EOF truncation
    -- marker following the @"EOF"@ trailer, if one was present.
    -- 'Nothing' means the patch did not declare a truncation and
    -- the final target size is implied by the largest record end.
    --
    -- The marker is a 'StandardIPS'-only extension, well-documented
    -- via Flips and the Archiveteam wiki. No authoritative source
    -- defines an 'IPS32' analogue, so slap's parser rejects trailing
    -- bytes after @"EEOF"@ as a 'SlapError' rather than accepting
    -- them as a truncation declaration. This field therefore has a
    -- parse-enforced invariant: for any 'IPSPatch' whose 'ipsVariant'
    -- is 'IPS32', 'ipsTruncatedTargetSize' is always 'Nothing'.
  } deriving (Show)

-- | The JSON metadata trailer an EBP patch carries after its IPS records:
-- four optional text fields, decoded at the parse layer by 'Slap.JSON.parseEBPMetadata'.
data EBPMetadata = EBPMetadata
  { ebpMetadataTitle       :: !(Maybe EncodedText)
  , ebpMetadataAuthor      :: !(Maybe EncodedText)
  , ebpMetadataDescription :: !(Maybe EncodedText)
  , ebpMetadataPatcher     :: !(Maybe EncodedText)
  } deriving (Show, Eq)

-- | An 'EBPMetadata' value with every field set to 'Nothing'. The
-- shape produced by 'Slap.JSON.parseEBPMetadata' on malformed input,
-- and the natural starting point on the create side when no metadata
-- has been supplied yet.
emptyEBPMetadata :: EBPMetadata
emptyEBPMetadata = EBPMetadata
  { ebpMetadataTitle       = Nothing
  , ebpMetadataAuthor      = Nothing
  , ebpMetadataDescription = Nothing
  , ebpMetadataPatcher     = Nothing
  }

-- | An EBP patch. Structurally, EBP is a 'StandardIPS' patch with a
-- trailing JSON metadata blob, so the type is a wrapper: an
-- 'IPSPatch' plus an 'EBPMetadata'. Threading a @'Maybe'
-- 'EBPMetadata'@ field through 'IPSPatch' instead would leave the
-- nonsense state (@'IPS32' + 'Just' metadata@) representable; the
-- separate wrapper keeps the IPS-plus-metadata shape honest.
--
-- Invariant: the underlying 'ipsVariant' is expected to be
-- 'StandardIPS'. EBP has no defined 'IPS32' analogue. The parser
-- only produces an 'EBPPatch' from a successfully-parsed
-- 'StandardIPS' stream; callers constructing 'EBPPatch' values
-- directly are expected to maintain the invariant.
data EBPPatch = EBPPatch
  { ebpBasePatch :: !IPSPatch
  , ebpMetadata  :: !EBPMetadata
  } deriving (Show)

-- | The three shapes an IPS-family parse can resolve to on the
-- success side, distinguished at the type level rather than
-- reconstructed downstream from error-channel pattern matches.
--
-- 'Slap.IPS.Parse' produces exactly one of these for any
-- 'PatchFileContents' whose magic bytes identified it as an
-- IPS-family patch and whose record stream passed the per-record
-- validation pass. Parse is still free to return 'Left SlapError'
-- for inputs that violate the wire format in ways this sum does
-- not cover: bad magic, ceiling overrun,
-- unrecognized trailing bytes after @"EOF"@/@"EEOF"@, and so on.
data IPSParseResult
  = IPSParseCleanIPS IPSPatch
    -- ^ A 'StandardIPS' or 'IPS32' patch whose record stream was
    -- closed by a well-formed EOF marker. The trailer after the
    -- marker was either absent, or a 3-byte post-EOF truncation
    -- marker (captured in 'ipsTruncatedTargetSize'). Covers every
    -- plain-IPS success case; EBP is the sibling constructor.
  | IPSParseCleanEBP EBPPatch
    -- ^ A 'StandardIPS' patch whose record stream was closed by a
    -- well-formed @"EOF"@ marker followed by bytes beginning with
    -- @'{'@ — the shape-level signature of an EBPatcher-style JSON
    -- metadata blob. The metadata is captured verbatim as opaque
    -- bytes; no schema validation happens at parse time.
  | IPSParseTruncated IPSVariant (Vector IPSRecord)
    -- ^ The record stream ran out of input before a matching EOF
    -- marker was found. The records that had been decoded up to
    -- that point are preserved in wire order, validated against the
    -- same ceiling and RLE-zero rules as the clean paths, and
    -- surfaced here so @info@ / @explain@ can still report usefully
    -- on partially-complete IPS files. 'Slap.IPS.Parse' pairs this
    -- variant with a 'NoEOFMarker' warning via the 'Parsed' channel.
    --
    -- The 'IPSVariant' is whatever the magic bytes identified before
    -- the record walk began — preserved here so callers that want
    -- to label a truncated-IPS32 patch differently from a
    -- truncated-IPS one have the information available.
    --
    -- A truncated parse never decides between plain IPS and EBP:
    -- the discriminator lives in the post-@"EOF"@ trailer bytes
    -- the truncation swallowed. The surviving records are therefore
    -- treated as plain-IPS records by 'Slap.SomePatch'; anything
    -- EBP-shaped lost to the truncation is unrecoverable.
  deriving (Show)

----------------------------------------------------------------------------
-- Named constants
----------------------------------------------------------------------------

-- | Magic bytes for the 'StandardIPS' variant (@"PATCH"@). Read by
-- the parser during variant discrimination and written by the
-- encoder at the head of every 'StandardIPS' and EBP patch.
ipsMagicBytes :: ByteString
ipsMagicBytes = ByteString8.pack "PATCH"

-- | Magic bytes for the 'IPS32' variant (@"IPS32"@).
ips32MagicBytes :: ByteString
ips32MagicBytes = ByteString8.pack "IPS32"

-- | Trailer bytes that close a 'StandardIPS' record stream (@"EOF"@).
ipsEOFMarkerBytes :: ByteString
ipsEOFMarkerBytes = ByteString8.pack "EOF"

-- | Trailer bytes that close an 'IPS32' record stream (@"EEOF"@).
ips32EEOFMarkerBytes :: ByteString
ips32EEOFMarkerBytes = ByteString8.pack "EEOF"

-- | Both the 'StandardIPS'/EBP and 'IPS32' magics are this long, though distinct at the byte level.
ipsMagicLength :: Length
ipsMagicLength = Length 5

ipsEOFMarkerLength :: Length
ipsEOFMarkerLength = Length 3

ips32EEOFMarkerLength :: Length
ips32EEOFMarkerLength = Length 4

-- | Length of the two-byte big-endian size field present in every
-- record (both copy and RLE), regardless of variant. For a copy
-- record this is the payload length that follows; for an RLE
-- record this is zero, used as a sentinel for "the following
-- bytes encode a run, not a payload".
ipsRecordSizeFieldLength :: Length
ipsRecordSizeFieldLength = Length 2

-- | Length of the fixed header of an IPS record: the offset field
-- (width depending on variant) followed by the two-byte size field.
-- Variable in its 'OffsetWidth' parameter because 'StandardIPS' and
-- 'IPS32' differ only in that width.
ipsRecordHeaderLength :: OffsetWidth -> Length
ipsRecordHeaderLength width =
  offsetWidthByteCount width <> ipsRecordSizeFieldLength

-- | Fixed-byte overhead of a copy record: the header, with a
-- non-zero size field indicating the payload length that follows.
-- Identical in bytes to 'ipsRecordHeaderLength'; named separately
-- so call sites can say what they mean.
ipsCopyRecordOverhead :: OffsetWidth -> Length
ipsCopyRecordOverhead = ipsRecordHeaderLength

-- | Length of the two-byte big-endian RLE count field. Present only
-- on RLE records, immediately after the zero-valued size sentinel.
ipsRleCountFieldLength :: Length
ipsRleCountFieldLength = Length 2

-- | Length of the one-byte RLE fill value. The byte is written to
-- the target verbatim @count@ times and is not a protocol-decoded
-- value, so it gets no role newtype in 'Slap.Measure'.
ipsRleFillByteLength :: Length
ipsRleFillByteLength = Length 1

-- | Total fixed-byte overhead of an RLE record: the header (with
-- zero in the size field), plus the RLE count field, plus the fill
-- byte. @'Length' 8@ for 'StandardIPS', @'Length' 9@ for 'IPS32'.
ipsRleRecordOverhead :: OffsetWidth -> Length
ipsRleRecordOverhead width =
     ipsRecordHeaderLength width
  <> ipsRleCountFieldLength
  <> ipsRleFillByteLength

-- | Maximum payload bytes a single copy record can carry. The
-- 16-bit size field caps this at @0xFFFF = 65535@, independent of
-- variant.
ipsMaxRecordPayload :: Length
ipsMaxRecordPayload = Length 0xFFFF

----------------------------------------------------------------------------
-- Per-variant dispatch
----------------------------------------------------------------------------

-- | Retrieve the wire facts for an 'IPSVariant'. A pure two-case
-- dispatch, and the one seam that everything else in 'Slap.IPS'
-- reaches for when it needs to know how the variants differ.
variantSpec :: IPSVariant -> IPSVariantSpec
variantSpec StandardIPS = IPSVariantSpec
  { ipsVariantMagic                = ipsMagicBytes
  , ipsVariantOffsetWidth          = Offset24
  , ipsVariantEOFMarker            = ipsEOFMarkerBytes
  , ipsVariantSentinel             = Offset (fromIntegral ipsSentinel)
  , ipsVariantMaxAddressableOffset = Offset 0xFFFFFF
  }
variantSpec IPS32 = IPSVariantSpec
  { ipsVariantMagic                = ips32MagicBytes
  , ipsVariantOffsetWidth          = Offset32
  , ipsVariantEOFMarker            = ips32EEOFMarkerBytes
  , ipsVariantSentinel             = Offset (fromIntegral ips32Sentinel)
  , ipsVariantMaxAddressableOffset = Offset 0xFFFFFFFF
  }

-- | The arithmetic spec ceiling for where a single record can end
-- in the given variant: the sum of 'ipsVariantMaxAddressableOffset'
-- (the largest offset a record can name in the variant) and
-- 'ipsMaxRecordPayload' (the largest payload the 16-bit size field
-- can carry, shared by both variants). A record whose
-- @offset + payloadLength@ exceeds this value cannot be represented
-- on the wire by any encoder that respects the format's offset and
-- size fields.
--
-- 'Slap.IPS.Parse' consumes this as its per-record acceptance bound.
-- 'Slap.IPS.Apply' trusts the parse precondition and does not
-- recompute the formula.
ipsVariantMaxRecordEnd :: IPSVariant -> Offset
ipsVariantMaxRecordEnd variant =
  advance (ipsVariantMaxAddressableOffset (variantSpec variant))
          ipsMaxRecordPayload

----------------------------------------------------------------------------
-- Encoding limits
----------------------------------------------------------------------------

-- | 'StandardIPS''s wire-format offset cap, paired with 'LabelIPS' for
-- error tagging. Consumed by 'Slap.Convert.encodingLimits' and by the
-- narrow-layer rejection tests; sibling to 'apsN64Limits',
-- 'pmsrLimits', 'ppf1Limits', 'ppf2Limits' — every direct format with
-- a per-record offset bound exports its 'EncodingLimits' from its own
-- @Types@ module.
ipsLimits :: EncodingLimits
ipsLimits = EncodingLimits
  { maximumOffset = ipsVariantMaxAddressableOffset (variantSpec StandardIPS)
  , formatLabel   = LabelIPS
  }

-- | 'IPS32''s wire-format offset cap, paired with 'LabelIPS32' for
-- error tagging. The 32-bit-offset sibling to 'ipsLimits'.
ips32Limits :: EncodingLimits
ips32Limits = EncodingLimits
  { maximumOffset = ipsVariantMaxAddressableOffset (variantSpec IPS32)
  , formatLabel   = LabelIPS32
  }

-- | EBP's wire-format offset cap. Structurally a 'StandardIPS' patch
-- with a JSON metadata trailer, so EBP shares 'ipsLimits''s offset
-- range; only the error-tag 'FormatLabel' differs. Defined here as a
-- record-update on 'ipsLimits' so the shared field stays in lockstep
-- with 'StandardIPS'.
ebpLimits :: EncodingLimits
ebpLimits = ipsLimits { formatLabel = LabelEBP }

----------------------------------------------------------------------------
-- Source/target size-pair rules
----------------------------------------------------------------------------

-- | 'StandardIPS' declines (source, target) pairs whose target is
-- both shorter than the source and too large for the truncation
-- marker to name. Shrinkage itself is the post-EOF marker's whole
-- purpose — but the marker spells the final size in the variant's
-- offset width, so a target size past
-- 'ipsVariantMaxAddressableOffset' has no representation: encoding
-- it would mask the size to its low 24 bits and emit a patch that
-- applies to a wrongly-sized file, with no checksum in the format to
-- notice. Growth and same-size pairs pass — they need no marker.
-- Consumed by 'Slap.Convert.rejectIncompatibleSizeChange' through
-- its 'CreateIPS' arm.
ipsRejectIncompatibleSizeChange
  :: FileSize -> FileSize -> Either SlapError ()
ipsRejectIncompatibleSizeChange sourceSize targetSize
  | targetSize >= sourceSize = Right ()
  | fileSizeToInt targetSize <= offsetToInt markerMaximum = Right ()
  | otherwise = Left (UnencodeablePair LabelIPS
      (TruncationTargetUnrepresentable
        (DeclaredTargetSize targetSize)
        (MaxOffset markerMaximum)))
  where
    markerMaximum = ipsVariantMaxAddressableOffset (variantSpec StandardIPS)

-- | IPS32 declines (source, target) pairs whose target is shorter
-- than the source. IPS32 has no truncation extension in its wire
-- vocabulary, so target shrinkage has no on-wire representation.
-- Consumed by 'Slap.Convert.rejectIncompatibleSizeChange' through
-- its 'CreateIPS32' arm.
ips32RejectIncompatibleSizeChange
  :: FileSize -> FileSize -> Either SlapError ()
ips32RejectIncompatibleSizeChange sourceSize targetSize
  | sourceSize <= targetSize = Right ()
  | otherwise                = Left (UnencodeablePair LabelIPS32
      (TargetShrinksBelowSource (ActualSize sourceSize) (ExpectedSize targetSize)))

-- | EBP declines (source, target) pairs whose target is shorter than
-- the source. EBP is structurally a 'StandardIPS' patch with a JSON
-- metadata trailer; the trailer slot is claimed by the JSON, leaving
-- no room for a truncation marker. Consumed by
-- 'Slap.Convert.rejectIncompatibleSizeChange' through its
-- 'CreateEBP' arm.
ebpRejectIncompatibleSizeChange
  :: FileSize -> FileSize -> Either SlapError ()
ebpRejectIncompatibleSizeChange sourceSize targetSize
  | sourceSize <= targetSize = Right ()
  | otherwise                = Left (UnencodeablePair LabelEBP
      (TargetShrinksBelowSource (ActualSize sourceSize) (ExpectedSize targetSize)))

----------------------------------------------------------------------------
-- Truncation-marker disposition
----------------------------------------------------------------------------

-- | What slap's policy decides to do with a 'StandardIPS' patch's
-- post-EOF truncation marker, given the marker's declared size and
-- the natural size derived from source plus records. Computed once
-- at the start of apply so the buffer allocation, the per-record
-- write loop, and the apply-time warnings all derive from the same
-- ground truth. Pattern-matched exhaustively at every consumer; a
-- future variant addition fires @-Wincomplete-patterns@.
data MarkerDisposition
  -- | No marker present. Effective target = natural. Silent.
  = MarkerAbsent NaturalTargetSize
  -- | Marker present and shrinks the output (@declared < natural@).
  -- Effective target = declared. Records past effective are clipped
  -- and counted; an apply-time warning surfaces the truncation, and
  -- a second warning surfaces the clip count if any records crossed.
  | MarkerHonored DeclaredTargetSize NaturalTargetSize
  -- | Marker present and exactly matches the natural size
  -- (@declared == natural@). Effective target = declared. Silent —
  -- the marker's assertion agrees with what slap was going to
  -- produce anyway, and surfacing this would generate noise on
  -- every patch that happens to truncate to a clean alignment.
  | MarkerNoOp DeclaredTargetSize
  -- | Marker present and would grow the output past natural
  -- (@declared > natural@). Effective target = natural; the marker
  -- is ignored for sizing per docs/ips/questions.md. Apply-time
  -- warning emitted.
  | MarkerIgnored DeclaredTargetSize NaturalTargetSize
  deriving (Show, Eq)

-- | Decide what slap does with the marker, given the patch's
-- declared truncation size (or 'Nothing' if absent) and the natural
-- size. Total, pure, the only place the comparison logic lives.
decideMarkerDisposition
  :: Maybe DeclaredTargetSize -> NaturalTargetSize -> MarkerDisposition
decideMarkerDisposition Nothing natural = MarkerAbsent natural
decideMarkerDisposition (Just declared) natural
  | declaredFileSize <  naturalFileSize = MarkerHonored declared natural
  | declaredFileSize == naturalFileSize = MarkerNoOp declared
  | otherwise                           = MarkerIgnored declared natural
  where
    declaredFileSize = unDeclaredTargetSize declared
    naturalFileSize  = unNaturalTargetSize  natural

-- | The buffer-allocation size implied by a 'MarkerDisposition'.
-- Total over the four constructors.
effectiveTargetSize :: MarkerDisposition -> FileSize
effectiveTargetSize (MarkerAbsent   natural)            = unNaturalTargetSize  natural
effectiveTargetSize (MarkerHonored declared _natural)  = unDeclaredTargetSize declared
effectiveTargetSize (MarkerNoOp     declared)           = unDeclaredTargetSize declared
effectiveTargetSize (MarkerIgnored  _declared natural)  = unNaturalTargetSize  natural

----------------------------------------------------------------------------
-- SNESTool truncation-shape filter
----------------------------------------------------------------------------

-- | Whether IPS create should refuse to emit a truncation marker
-- whose declared target size doesn't satisfy SNESTool's
-- @(size & 0xFFF) == 0x200@ shape filter. SNESTool — MCA\/Elite,
-- DOS, 1996 — was the format's earliest applier; its IPS apply
-- loop rejects markers that don't match the bit pattern an
-- SMC-headered SNES ROM exhibits. The IPS spec
-- itself imposes no such constraint, and every modern applier
-- (Flips, RomPatcher.js) accepts any wire-valid marker. Only
-- SNESTool filters.
--
-- Users who specifically target SNESTool can opt into the refusal
-- at create time by setting 'RequireSMCShapedTruncation'. The
-- default 'AllowAnyTruncationShape' produces the patch slap has
-- always produced. Evidence trail: @docs\/ips\/ips2-snestool-report.md@.
data SMCShapeRequirement
  = AllowAnyTruncationShape
  | RequireSMCShapedTruncation
  deriving (Show, Eq)

-- | Predicate matching SNESTool's truncation-marker size filter,
-- transcribed from SNESTL12.EXE at image offset 0xB6F-0xB77:
--
-- @
--   AND CX, 0x0FFF
--   CMP CX, 0x0200
--   JZ  ok
-- @
--
-- That is, @size .&. 0xFFF == 0x200@ — equivalently
-- @size \`mod\` 4096 == 512@. The motivating case is the canonical
-- SMC-headered SNES ROM: a commercial header-stripped ROM payload
-- is a multiple of 4 KiB, and the 512-byte SMC copier header tacks
-- an extra 0x200 onto the size, so a real headered SMC ROM passes.
-- The check is necessary but not sufficient for
-- SMC-ness — a hypothetical 0x1200-byte file also passes — but
-- that looseness is in MCA's binary; slap reproduces the binary's
-- predicate verbatim.
isSMCShapedSize :: FileSize -> Bool
isSMCShapedSize (FileSize n) = n .&. 0xFFF == 0x200
