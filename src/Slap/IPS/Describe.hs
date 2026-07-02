-- | Describe layer for the IPS family — the per-patch metadata
-- ('ipsMeta', 'ebpMeta') and structured 'PatchAnalysis' builders
-- ('analyzeIPS', 'analyzeEBP'). The analytical builders feed
-- 'Slap.SomePatch.patchAnalysis' (lazy; only forced by @slap
-- explain@); the 'ipsMeta' / 'ebpMeta' helpers feed @infoLines@
-- on 'Slap.SomePatch.patchInfo', which is what @slap info@ and
-- @slap apply@ read. Counterparts to 'Slap.BPS.Describe.analyzeBPS'
-- / 'Slap.BPS.Describe.bpsMeta' and 'Slap.UPS.Describe.analyzeUPS'
-- / 'Slap.UPS.Describe.upsMeta'. Rendering lives in 'Slap.Display.Analysis'
-- / @doInfo@ / @doExplain@ in @app/Main.hs@, not here.
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
-- paths here — only rendering. EBP metadata reaches Describe as a
-- structured 'EBPMetadata' record: the JSON parsing happens in
-- 'Slap.IPS.Parse' (via 'Slap.JSON.parseEBPMetadata') so every
-- consumer reads the four fields directly. Describe then renders
-- whichever fields are present — and surfaces a single placeholder
-- line when none are, the shape an all-absent malformed-metadata
-- patch produces.
{-# LANGUAGE OverloadedStrings #-}

module Slap.IPS.Describe
  ( -- * Plain IPS
    ipsMeta
  , analyzeIPS
    -- * EBP-wrapped IPS
  , ebpMeta
  , analyzeEBP
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
import Slap.Text (EncodedText, encodedTextContent)
import Slap.Display.Analysis
  ( PatchAnalysis(..)
  , AnalysisSection(..)
  , AnalysisRegion(..)
  , AnalysisPayload(..)
  , AnalysisSummary(..)
  , SummaryInfo(..)
  , Annotation(..)
  , OffsetKind(..)
  , AnnotDetail(..)
  )
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), ByteCount(..), renderAsText)
import Slap.Display.Primitives (padHex, renderPrintableASCIIOrHex)
import Slap.Measure (Offset(Offset), FileSize(..),
                     OffsetRange(..), advance, distance)

import Data.Vector (Vector)

import Data.ByteString (ByteString)
import Data.Maybe (isNothing)
import Data.Text (Text)
import qualified Data.Vector as Vector

----------------------------------------------------------------------------
-- ipsMeta — plain IPSPatch
----------------------------------------------------------------------------

-- | One-line-per-field metadata for an 'IPSPatch'.
-- The truncation line is emitted only when the parser observed a post-EOF truncation marker.
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

-- | The optional truncation field.
-- @Just n@ renders as a single @"truncate"@ line stating the post-apply target size;
-- 'Nothing' emits no line at all (no @"no truncation"@ noise).
truncationInfoLine :: Maybe FileSize -> [InfoLine]
truncationInfoLine Nothing =
  []
truncationInfoLine (Just truncatedTargetSize) =
  [InfoLine "truncate" (renderAsText (unFileSize truncatedTargetSize) <> " bytes")]

----------------------------------------------------------------------------
-- ebpMeta — EBP-wrapped IPSPatch
----------------------------------------------------------------------------

-- | One-line-per-field metadata for an 'EBPPatch'. Delegates the
-- wire-fact fields to 'ipsMeta' on the underlying 'IPSPatch', then
-- appends one line per populated metadata field — @title@, @author@,
-- @description@, @patcher@, in that declared order.
-- Absent fields produce no line.
--
-- The all-'Nothing' shape is also what 'Slap.JSON.parseEBPMetadata'
-- returns when the wire metadata bytes were malformed; in that case
-- a single @metadata@ line surfaces the absence directly. The
-- companion 'EBPMetadataMalformed' advisory has already told the
-- user why at parse time, so this line just notes that there is
-- nothing readable to show.
ebpMeta :: EBPPatch -> [InfoLine]
ebpMeta patch =
  ipsMeta (ebpBasePatch patch)
  ++ ebpMetadataInfoLines (ebpMetadata patch)

-- | One 'InfoLine' per populated EBP metadata field. The field
-- ordering matches the JSON wire shape (@patcher@ first on emit,
-- but title / author / description first in user-facing display);
-- here we lead with the user-facing three and trail with @patcher@
-- so the patch's authorship reads top-to-bottom and the producer
-- identity sits at the bottom. The all-absent case collapses to a
-- single placeholder line — see the 'ebpMeta' Haddock for why.
ebpMetadataInfoLines :: EBPMetadata -> [InfoLine]
ebpMetadataInfoLines metadata
  | allAbsent =
      [InfoLine "metadata" "(no readable fields; see parse-time advisory if malformed)"]
  | otherwise = concat
      [ renderField "title"       (ebpMetadataTitle       metadata)
      , renderField "author"      (ebpMetadataAuthor      metadata)
      , renderField "description" (ebpMetadataDescription metadata)
      , renderField "patcher"     (ebpMetadataPatcher     metadata)
      ]
  where
    allAbsent = isNothing (ebpMetadataTitle       metadata)
             && isNothing (ebpMetadataAuthor      metadata)
             && isNothing (ebpMetadataDescription metadata)
             && isNothing (ebpMetadataPatcher     metadata)

-- | Emit one 'InfoLine' for a populated EBP metadata field, or
-- nothing for an absent one. The displayed text is the field's
-- 'Text' content verbatim — the encoding tag has already done its
-- job by the time the value reaches Describe (JSON was decoded as
-- UTF-8 at parse time), so the user sees real codepoints.
renderField :: Text -> Maybe EncodedText -> [InfoLine]
renderField _      Nothing      = []
renderField label  (Just value) =
  [InfoLine label (encodedTextContent value)]

----------------------------------------------------------------------------
-- analyze — structured analysis for the explain renderer
----------------------------------------------------------------------------

-- | Build a 'PatchAnalysis' for a plain 'IPSPatch'. Every record
-- becomes one 'AnalysisRegion' via 'makeIPSRegion'; the summary
-- reports the record count and the total bytes that the stream
-- would write to the target.
--
-- The record walk stays lazy over the underlying 'Vector' via
-- 'Vector.toList': 'renderAnalysisFull' consumes the region list in
-- order, so materialising the whole list is not a
-- 7000-records-at-once memory hit. The total-bytes computation uses
-- a strict 'Vector.foldl'' so the traversal is a single pass and
-- the accumulator cannot build a thunk chain even on the
-- stadium2-scale @.ips32@ fixture.
analyzeIPS :: IPSPatch -> PatchAnalysis
analyzeIPS patch = PatchAnalysis
  { analysisSections =
      [ SectionRegions
          (map makeIPSRegion (Vector.toList (ipsRecords patch))) ]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records
                                  (Just (TotalPayloadBytes totalBytes)))
  }
  where
    recordVector = ipsRecords patch
    recordCount  = Vector.length recordVector
    totalBytes   = Vector.foldl'
                     (\runningTotal record ->
                        runningTotal <> recordPayloadLength record)
                     mempty
                     recordVector

-- | Build a 'PatchAnalysis' for an 'EBPPatch'. Delegates entirely to
-- 'analyzeIPS' on the underlying base patch — the EBP wrapper adds
-- only header metadata (a 'metadata' line in 'ebpMeta'), not new
-- region shape, so the analytical breakdown is identical to plain
-- IPS. The format-name distinction comes from 'patchInfo' on the
-- 'Slap.SomePatch.SomePatch' record, not from the analytical
-- carrier.
analyzeEBP :: EBPPatch -> PatchAnalysis
analyzeEBP = analyzeIPS . ebpBasePatch

-- | Build a single 'AnalysisRegion' from an 'IPSRecord'.
-- The offset and the region size are both taken from the constructor-agnostic 'ipsRecordOffset' and 'recordPayloadLength' helpers.
makeIPSRegion :: IPSRecord -> AnalysisRegion
makeIPSRegion record = AnalysisRegion
  { regionOffset     = recordTargetOffset
  , regionSize       = recordPayloadLength record
  , regionLabel      = regionLabelString
  , regionPayload    = regionPayloadValue
  , regionAnnotation = AnnotationAt AtOffset recordTargetOffset annotationDetails
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

-- | Human-readable rendering of an 'OffsetWidth'. Used by
-- 'ipsVariantInfoLines' so the reader sees @"24-bit"@ rather than
-- a bare @3@ byte count. The 3 / 4 byte-count mapping still lives
-- only in 'Slap.IPS.Types.offsetWidthByteCount'; this helper is a
-- parallel display mapping that never touches the byte count.
renderOffsetWidth :: OffsetWidth -> Text
renderOffsetWidth Offset24 = "24-bit"
renderOffsetWidth Offset32 = "32-bit"

-- | Render a variant's maximum addressable offset as a zero-padded
-- hex literal. Eight hex digits accommodates the largest
-- 'IPS32' ceiling (@0xFFFFFFFF@); 'StandardIPS''s smaller
-- @0xFFFFFF@ gets the same eight-digit padding for visual
-- alignment across variants.
renderMaxOffset :: Offset -> Text
renderMaxOffset (Offset offsetValue) = "0x" <> padHex 8 offsetValue

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty IPS record stream. Used by
-- the cheap display path's 'Slap.Display.Info.PatchInfo' construction
-- on plain IPS, IPS32, and EBP — all three carry the same record
-- shape, so a single helper covers them.
-- 'Nothing' on an empty stream keeps the display layer from printing an empty @0x0 - 0x0@ range line.
ipsRecordsRange :: Vector IPSRecord -> Maybe OffsetRange
ipsRecordsRange records
  | Vector.null records = Nothing
  | otherwise =
      let firstAffectedOffset = Vector.minimum (Vector.map ipsRecordOffset records)
          endOfLastRecord     = Vector.maximum (Vector.map recordEndOffset records)
      in Just OffsetRange
          { rangeStart  = firstAffectedOffset
          , rangeLength = distance firstAffectedOffset endOfLastRecord
          }
  where
    recordEndOffset record =
      advance (ipsRecordOffset record) (recordPayloadLength record)

----------------------------------------------------------------------------
-- Shape-recognized byte display
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
renderMarkerBytes :: ByteString -> Text
renderMarkerBytes = renderPrintableASCIIOrHex


