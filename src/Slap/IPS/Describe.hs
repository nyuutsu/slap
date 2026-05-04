-- | Describe layer for the IPS family — the per-patch metadata
-- ('ipsMeta', 'ebpMeta') and structured 'ExplainData' builders
-- ('explainIPS', 'explainEBP') consumed by slap's @info@ and
-- @explain@ verbs. Both verbs read these via the 'patchExplain'
-- field on a parsed 'Slap.SomePatch.SomePatch'; rendering lives in
-- @doInfo@ and @doExplain@ in @app/Main.hs@, not here.
-- Counterparts to 'Slap.BPS.Describe.explainBPS' / 'Slap.BPS.Describe.bpsMeta'
-- and 'Slap.UPS.Describe.explainUPS' / 'Slap.UPS.Describe.upsMeta'.
--
-- Two top-level function families rather than one taking an
-- @Either IPSPatch EBPPatch@: 'Slap.IPS.Parse' already discriminates
-- plain IPS from EBP-wrapped on the parse-result side, and making
-- Describe re-discriminate would duplicate the case for no benefit.
-- The caller (currently 'Slap.SomePatch') routes on the parse
-- result and hands the right patch to the right function.
--
-- Describe trusts its inputs. Every value reaching this module has
-- already been validated by 'Slap.IPS.Parse', so there are no error
-- paths here — only rendering. In particular, EBP metadata is
-- treated as an opaque byte blob for display purposes: the
-- @title@/@author@/@description@ extraction the old Describe layer
-- did is gone on purpose, because it reached past the
-- "shape-recognize, don't schema-validate" boundary that
-- 'Slap.IPS.Parse' draws.
module Slap.IPS.Describe
  ( -- * Plain IPS
    ipsMeta
  , explainIPS
    -- * EBP-wrapped IPS
  , ebpMeta
  , explainEBP
    -- * Region builder
  , makeIPSRegion
    -- * Display range
  , ipsRecordsRange
  ) where

import Slap.IPS.Types
  ( IPSVariant(..)
  , OffsetWidth(..)
  , IPSVariantSpec(..)
  , IPSRecord(..)
  , IPSPatch(..)
  , EBPMetadata(..)
  , EBPPatch(..)
  , ipsRecordOffset
  , recordPayloadLength
  , variantSpec
  )
import Slap.Explain
  ( ExplainData(..)
  , ExplainSection(..)
  , ExplainRegion(..)
  , ExplainPayload(..)
  , ExplainSummary(..)
  , SummaryInfo(..)
  , SummaryByteInfo(..)
  , SummaryBytes(..)
  , Annotation(..)
  , OffsetKind(..)
  , AnnotDetail(..)
  )
import Slap.Display (InfoLine(..))
import Slap.Format (padHex, renderPrintableASCIIOrHex, renderUTF8OrByteCount)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     OffsetRange(..), advance)

import Data.Vector (Vector)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

----------------------------------------------------------------------------
-- ipsMeta — plain IPSPatch
----------------------------------------------------------------------------

-- | One-line-per-field metadata for an 'IPSPatch'. The variant's
-- wire facts come from 'variantSpec' so nothing in this module
-- hardcodes @"PATCH"@ / @"IPS32"@ / @"EOF"@ / @"EEOF"@ strings or
-- the 24/32-bit offset widths. The truncation line is emitted
-- only when the parser observed a post-EOF truncation marker.
ipsMeta :: IPSPatch -> [InfoLine]
ipsMeta patch =
  ipsVariantInfoLines (ipsVariant patch)
  ++ truncationInfoLine (ipsTruncatedTargetSize patch)

-- | The per-variant wire-fact meta fields that both 'ipsMeta' and
-- 'ebpMeta' emit. Pulled from 'variantSpec' to keep Describe from
-- owning its own copy of the magic/marker/width/ceiling facts.
-- Shared between the plain and EBP paths because EBP wraps a
-- 'StandardIPS' record stream and the underlying wire facts are
-- worth surfacing regardless of wrapper.
ipsVariantInfoLines :: IPSVariant -> [InfoLine]
ipsVariantInfoLines variant =
  let spec = variantSpec variant
  in [ InfoLine "magic"      (renderMarkerBytes (ipsVariantMagic spec))
     , InfoLine "offset"     (renderOffsetWidth (ipsVariantOffsetWidth spec))
     , InfoLine "EOF marker" (renderMarkerBytes (ipsVariantEOFMarker spec))
     , InfoLine "max offset" (renderMaxOffset    (ipsVariantMaxAddressableOffset spec))
     ]

-- | The optional truncation field. @Just n@ renders as a single
-- @"truncate"@ line stating the post-apply target size; 'Nothing'
-- emits no line at all (no @"no truncation"@ noise).
truncationInfoLine :: Maybe FileSize -> [InfoLine]
truncationInfoLine Nothing =
  []
truncationInfoLine (Just truncatedTargetSize) =
  [InfoLine "truncate" (show (unFileSize truncatedTargetSize) ++ " bytes")]

----------------------------------------------------------------------------
-- ebpMeta — EBP-wrapped IPSPatch
----------------------------------------------------------------------------

-- | One-line-per-field metadata for an 'EBPPatch'. Delegates the
-- wire-fact fields to 'ipsMeta' on the underlying 'IPSPatch', then
-- appends a single @metadata@ line carrying the blob byte count and
-- a shape-recognized preview. Shape-only: the preview is either the
-- raw bytes decoded as ASCII (when every previewed byte is
-- printable) or a hex dump (when any byte is not). The JSON is
-- never parsed past that.
ebpMeta :: EBPPatch -> [InfoLine]
ebpMeta patch =
  ipsMeta (ebpBasePatch patch)
  ++ [ InfoLine "metadata"
         (renderEBPMetadata (unEBPMetadata (ebpMetadata patch))) ]

----------------------------------------------------------------------------
-- explain — structured description for the explain renderer
----------------------------------------------------------------------------

-- | Build structured 'ExplainData' for a plain 'IPSPatch'. Every
-- record becomes one 'ExplainRegion' via 'makeIPSRegion'; the
-- patch-level header reuses 'ipsMeta'; the summary reports the
-- record count and the total bytes that the stream would write to
-- the target.
--
-- The record walk stays lazy over the underlying 'Vector' via
-- 'Vector.toList': 'renderExplain' consumes the region list in
-- order, so materialising the whole list is not a
-- 7000-records-at-once memory hit. The total-bytes computation uses
-- a strict 'Vector.foldl'' so the traversal is a single pass and
-- the accumulator cannot build a thunk chain even on the
-- stadium2-scale @.ips32@ fixture.
explainIPS :: IPSPatch -> ExplainData
explainIPS patch = ExplainData
  { explainFormat   = ipsVariantDisplayName (ipsVariant patch)
  , explainHeader   = ipsMeta patch
  , explainSections =
      [ SectionRegions
          (map makeIPSRegion (Vector.toList (ipsRecords patch))) ]
  , explainSummary  = Summary (SummaryInfo recordCount "records"
                                 (Just (SummaryByteInfo totalBytes BytesTotal)))
  , explainNotes    = []
  }
  where
    recordVector = ipsRecords patch
    recordCount  = Vector.length recordVector
    totalBytes   = Vector.foldl'
                     (\runningTotal record ->
                        runningTotal + unLength (recordPayloadLength record))
                     0
                     recordVector

-- | Build structured 'ExplainData' for an 'EBPPatch'. Delegates to
-- 'explainIPS' for the record walk and summary, then rewrites the
-- format name to @"EBP"@ and swaps the header for 'ebpMeta' so the
-- metadata line shows up in the explain output alongside the
-- variant facts.
explainEBP :: EBPPatch -> ExplainData
explainEBP patch =
  (explainIPS (ebpBasePatch patch))
    { explainFormat = "EBP"
    , explainHeader = ebpMeta patch
    }

-- | Build a single 'ExplainRegion' from an 'IPSRecord'. Copy records
-- become 'PayloadWrite' regions carrying their literal bytes; RLE
-- records become 'PayloadFill' regions tagged with 'DetailRLE'.
-- The offset and the region size are both taken from the
-- constructor-agnostic 'ipsRecordOffset' and 'recordPayloadLength'
-- helpers, so this walk never re-pattern-matches to recompute
-- either.
makeIPSRegion :: IPSRecord -> ExplainRegion
makeIPSRegion record = ExplainRegion
  { regionOffset     = recordTargetOffset
  , regionSize       = recordPayloadLength record
  , regionLabel      = regionLabelString
  , regionPayload    = regionPayloadValue
  , regionAnnotation = AnnotAt AtOffset recordTargetOffset annotationDetails
  }
  where
    recordTargetOffset = ipsRecordOffset record
    (regionLabelString, regionPayloadValue, annotationDetails) = case record of
      IPSRecordCopy { ipsCopyPayload = payload } ->
        ("Write  ", PayloadWrite payload, [])
      IPSRecordRLE  { ipsRleCount = runLength
                    , ipsRleFill  = fillByte } ->
        ("Fill ",   PayloadFill fillByte runLength, [DetailRLE])

----------------------------------------------------------------------------
-- Display helpers
----------------------------------------------------------------------------

-- | The human-facing format name for an 'IPSVariant'. Used on the
-- @format:@ line by 'explainIPS'. Not a wire fact (the bytes are
-- in 'ipsVariantMagic'; this is a different thing — what the user
-- calls the variant in prose) and therefore not on
-- 'IPSVariantSpec'. 'EBPPatch' does not use this helper — it
-- hardcodes @"EBP"@ because EBP is a wrapper format and its
-- underlying variant is always 'StandardIPS' by invariant.
ipsVariantDisplayName :: IPSVariant -> String
ipsVariantDisplayName StandardIPS = "IPS"
ipsVariantDisplayName IPS32       = "IPS32"

-- | Human-readable rendering of an 'OffsetWidth'. Used by
-- 'ipsVariantInfoLines' so the reader sees @"24-bit"@ rather than
-- a bare @3@ byte count. The 3 / 4 byte-count mapping still lives
-- only in 'Slap.IPS.Types.offsetWidthByteCount'; this helper is a
-- parallel display mapping that never touches the byte count.
renderOffsetWidth :: OffsetWidth -> String
renderOffsetWidth Offset24 = "24-bit"
renderOffsetWidth Offset32 = "32-bit"

-- | Render a variant's maximum addressable offset as a zero-padded
-- hex literal. Eight hex digits accommodates the largest
-- 'IPS32' ceiling (@0xFFFFFFFF@); 'StandardIPS''s smaller
-- @0xFFFFFF@ gets the same eight-digit padding for visual
-- alignment across variants.
renderMaxOffset :: Offset -> String
renderMaxOffset (Offset offsetValue) = "0x" ++ padHex 8 offsetValue

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty IPS record stream. Used by
-- the cheap display path's 'Slap.Display.PatchHeader' construction
-- on plain IPS, IPS32, and EBP — all three carry the same record
-- shape, so a single helper covers them. Returns 'Nothing' on an
-- empty stream so the display layer suppresses the range line
-- rather than printing a degenerate @0x0 - 0x0@.
ipsRecordsRange :: Vector IPSRecord -> Maybe OffsetRange
ipsRecordsRange records
  | Vector.null records = Nothing
  | otherwise =
      let firstAffectedOffset = Vector.minimum (Vector.map ipsRecordOffset records)
          endOfLastRecord     = Vector.maximum (Vector.map recordEndOffset records)
      in Just OffsetRange
          { rangeStart  = firstAffectedOffset
          , rangeLength = Length (unOffset endOfLastRecord - unOffset firstAffectedOffset)
          }
  where
    recordEndOffset record =
      advance (ipsRecordOffset record) (recordPayloadLength record)

----------------------------------------------------------------------------
-- Shape-recognised byte display
----------------------------------------------------------------------------

-- | Render a raw marker byte sequence (the variant's magic or EOF
-- marker, as it appears on the wire) for inclusion in an 'InfoLine'.
-- Returns the bytes decoded as ASCII when every byte is in the
-- printable ASCII range — the common case for every variant slap
-- supports, since @"PATCH"@, @"IPS32"@, @"EOF"@, and @"EEOF"@ are
-- all printable — and falls back to a hex dump when any byte is
-- outside that range. The fallback exists so a hypothetical future
-- variant with a non-ASCII marker still renders legibly instead of
-- smuggling control bytes into the info stream.
renderMarkerBytes :: ByteString -> String
renderMarkerBytes = renderPrintableASCIIOrHex

-- | Render a raw EBP metadata blob for the @metadata:@ header field:
-- the byte count followed by a shape-recognised preview of the
-- leading 'metadataPreviewBytes' bytes. EBP metadata is UTF-8 by
-- convention (per the EBPatcher reference implementation), so the
-- preview decodes as UTF-8 when valid and falls back to a byte count
-- description when not. The function deliberately does not parse,
-- validate, or extract fields from the JSON — that line is drawn in
-- 'Slap.IPS.Parse' and Describe honours it.
renderEBPMetadata :: ByteString -> String
renderEBPMetadata metadataBytes
  | ByteString.null metadataBytes =
      "(none)"
  | otherwise =
      show (ByteString.length metadataBytes) ++ " bytes: "
      ++ renderUTF8OrByteCount metadataPreviewBytes metadataBytes

-- | Maximum number of EBP metadata bytes shown in 'renderEBPMetadata'
-- before the preview is truncated with an ellipsis. Matches BPS's
-- 'Slap.BPS.Describe.metadataPreviewBytes' for consistency — both
-- formats cap metadata previews at the same length so @slap info@
-- output doesn't flood the terminal on a large blob.
metadataPreviewBytes :: Int
metadataPreviewBytes = 200

