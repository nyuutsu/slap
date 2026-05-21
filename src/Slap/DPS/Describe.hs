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
                     Tally(..), CountUnit(..), ByteCount(..))
import Slap.Measure (Length(..), FileSize(..), byteLength)
import Slap.Text (EncodedText, encodedTextContent)

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
  , [InfoLine "orig size" (show (unFileSize (dpsSourceSizeAsFileSize (dpsOriginalSize patch))))]
  , [InfoLine "flag" "unstable" | dpsStability patch == DPSUnstable]
  , [InfoLine "copy" (show copyCount)]
  , [InfoLine "enclosed" (show enclosedCount)]
  ]
  where
    -- The decoded text comes off the typed field directly; empty
    -- fields suppress their info line. Trailing null bytes (the
    -- wire's 64-byte field is null-padded) are dropped before render.
    fieldPair :: String -> EncodedText -> [InfoLine]
    fieldPair label value
      | Text.null trimmed = []
      | otherwise         = [InfoLine label (Text.unpack trimmed)]
      where
        trimmed = Text.dropWhileEnd (== '\NUL') (encodedTextContent value)
    copyCount = length [() | DPSCopyFromROM {} <- dpsRecords patch]
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
