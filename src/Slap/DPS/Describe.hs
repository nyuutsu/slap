{-# LANGUAGE OverloadedStrings #-}

module Slap.DPS.Describe
  ( dpsMeta
  , analyzeDPS
  , makeDPSRegion
  ) where

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), DPSStability(..),
                       dpsSourceSizeAsFileSize)
import Slap.Display.Analysis
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Display.Common (InfoLine(..),
                     Tally(..), CountUnit(..), ByteCount(..), renderAsText)
import Slap.Measure (Length(..), FileSize(..), byteLength)
import Slap.Text (EncodedText, encodedTextContent)

import Data.Text (Text)
import qualified Data.ByteString as ByteString
import qualified Data.Text as Text

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

dpsMeta :: DPSPatch -> [InfoLine]
dpsMeta patch = concat
  [ fieldPair "name"    (dpsName patch)
  , fieldPair "author"  (dpsAuthor patch)
  , fieldPair "version" (dpsVersion patch)
  , [InfoLine "orig size" (renderAsText (unFileSize (dpsSourceSizeAsFileSize (dpsOriginalSize patch))))]
  , [InfoLine "flag" "unstable" | dpsStability patch == DPSUnstable]
  , [InfoLine "breakdown" recordKindBreakdown]
  ]
  where
    -- Fields are trimmed to their content at parse time; show each, or
    -- nothing when it was blank padding.
    fieldPair :: Text -> EncodedText -> [InfoLine]
    fieldPair label value
      | Text.null content = []
      | otherwise         = [InfoLine label content]
      where
        content = encodedTextContent value
    -- DPS records split into two kinds. The count line already states
    -- the total ("401 records"), so this row breaks that total down
    -- rather than spending a line apiece on two numbers that sum to it.
    recordKindBreakdown =
      renderAsText copyCount <> " copy, " <> renderAsText enclosedCount <> " enclosed"
    copyCount     = length [() | DPSCopyFromROM {}  <- dpsRecords patch]
    enclosedCount = length [() | DPSEnclosedData {} <- dpsRecords patch]

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

analyzeDPS :: DPSPatch -> PatchAnalysis
analyzeDPS patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeDPSRegion (dpsRecords patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    recordCount = length (dpsRecords patch)
    totalBytes = sum (map recordBytes (dpsRecords patch))
    recordBytes DPSEnclosedData { dpsDataPayload } = ByteString.length dpsDataPayload
    recordBytes DPSCopyFromROM { dpsCopyLength }   = unLength dpsCopyLength

makeDPSRegion :: DPSRecord -> AnalysisRegion
makeDPSRegion (DPSEnclosedData outputOffset payload) = AnalysisRegion
  { regionOffset     = outputOffset
  , regionSize       = byteLength payload
  , regionLabel      = "Data   "
  , regionPayload    = PayloadWrite payload
  , regionAnnotation = AnnotationAt AtOffset outputOffset []
  }
makeDPSRegion (DPSCopyFromROM outputOffset sourceOffset copyLength) = AnalysisRegion
  { regionOffset     = outputOffset
  , regionSize       = copyLength
  , regionLabel      = "Copy   "
  , regionPayload    = PayloadCopy FromSource
  , regionAnnotation = AnnotationAt AtOffset outputOffset [DetailSource sourceOffset]
  }
