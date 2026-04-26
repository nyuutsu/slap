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
  , EBPMetadataFields(..)
  , EBPPatch(..)
  , IPSParseResult(..)
  , SMCShapeRequirement(..)
  , isSMCShapedSize
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
  ) where

import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as ByteString8
import Data.Vector (Vector)
import Data.Word (Word8)
import Slap.Measure
  ( Offset(..)
  , Length(..)
  , FileSize(..)
  , Cursor(..)
  , byteLength
  , ipsSentinel
  , ips32Sentinel
  )

-- | Which IPS variant a patch belongs to. The two variants are
-- wire-level distinct: 'StandardIPS' uses @PATCH@/@EOF@ framing with
-- 24-bit record offsets, while 'IPS32' uses @IPS32@/@EEOF@ framing
-- with 32-bit record offsets. EBP is not a distinct variant at this
-- layer — structurally, an EBP patch is a 'StandardIPS' patch with
-- a trailing JSON metadata blob, modelled as 'EBPPatch' wrapping an
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

-- | The byte count occupied by an 'OffsetWidth' in the wire format.
-- The one place the 3/4 mapping lives; callers receive a 'Length'
-- and never touch the raw integer.
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

-- | The number of bytes a single 'IPSRecord' will write to the
-- target when applied. For a copy record this is the payload byte
-- length; for an RLE record this is the run length. Used by both
-- 'Slap.IPS.Parse' (for the per-record ceiling check's end-offset
-- computation) and 'Slap.IPS.Apply' (for the target-size derivation
-- and the per-record bounds guard). Lives here in 'Slap.IPS.Types'
-- rather than at either call site because the concept is variant-
-- agnostic and constructor-aware in the same constructor-agnostic
-- way 'ipsRecordOffset' is.
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
  -- 'ByteString'. Stored as a 'Vector' rather than a list for the
  -- same reason BPS stores its action stream as one: the
  -- stadium2-scale @.ips32@ fixture is ~27 MB of proportionally
  -- many records, and a single contiguous array of pointers is
  -- kinder to the GC during apply than millions of individually
  -- allocated cons cells would be.
  , ipsRecords             :: !(Vector IPSRecord)
  , ipsTruncatedTargetSize :: !(Maybe FileSize)
    -- ^ The target file size declared by a Flips-style truncation
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

-- | The raw JSON metadata blob that trails an EBP patch. These are
-- the UTF-8 bytes of an EBPatcher-style JSON object, stored
-- verbatim — slap does not parse or validate the JSON at this
-- layer. The reference implementation emits exactly four fields
-- (@patcher@, @title@, @author@, @description@); slap's Describe
-- pass extracts the three user-facing fields leniently, but
-- everything below Describe treats the blob as opaque bytes.
newtype EBPMetadata = EBPMetadata { unEBPMetadata :: ByteString }
  deriving (Eq, Show)

-- | Structured input for 'buildEBPMetadataJSON'. The three fields
-- slap emits in EBP metadata blobs, following the EBPatcher
-- convention. The @patcher@ field is always set to @"slap"@ by
-- 'buildEBPMetadataJSON' itself and is not exposed here.
data EBPMetadataFields = EBPMetadataFields
  { ebpMetadataTitle       :: !String
  , ebpMetadataAuthor      :: !String
  , ebpMetadataDescription :: !String
  } deriving (Show, Eq)

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
-- not cover — bad magic, ceiling overrun, zero-count RLE,
-- unrecognised trailing bytes after @"EOF"@/@"EEOF"@, and so on.
data IPSParseResult
  = IPSParseCleanIPS IPSPatch
    -- ^ A 'StandardIPS' or 'IPS32' patch whose record stream was
    -- closed by a well-formed EOF marker. The trailer after the
    -- marker was either absent, or a Flips-style 3-byte truncation
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

-- | Length of the 'StandardIPS' magic (@"PATCH"@) at the start of
-- every 'StandardIPS' or EBP patch. The 'IPS32' magic happens to be
-- the same length but is distinct at the bytes level.
ipsMagicLength :: Length
ipsMagicLength = Length 5

-- | Length of the 'StandardIPS' @"EOF"@ trailer.
ipsEOFMarkerLength :: Length
ipsEOFMarkerLength = Length 3

-- | Length of the 'IPS32' @"EEOF"@ trailer.
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
-- SNESTool truncation-shape filter
----------------------------------------------------------------------------

-- | Whether IPS create should refuse to emit a truncation marker
-- whose declared target size doesn't satisfy SNESTool's
-- @(size & 0xFFF) == 0x200@ shape filter. SNESTool — MCA\/Elite,
-- DOS, 1996 — was the format's earliest applier; its IPS apply
-- loop rejects markers that don't match the bit pattern an
-- SMC-headered SNES ROM exhibits by construction. The IPS spec
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
-- an extra 0x200 onto the size, so a real headered SMC ROM passes
-- by construction. The check is necessary but not sufficient for
-- SMC-ness — a hypothetical 0x1200-byte file also passes — but
-- that looseness is in MCA's binary; slap reproduces the binary's
-- predicate verbatim.
isSMCShapedSize :: FileSize -> Bool
isSMCShapedSize (FileSize n) = n .&. 0xFFF == 0x200
