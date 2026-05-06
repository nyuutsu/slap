module Slap.GDIFF.Describe
  ( gdiffMeta
  , analyzeGDIFF
  , makeGDIFFRegion
  ) where

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..))
import Slap.Display.Analysis
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..), Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), advance, byteLength)

import qualified Data.ByteString as ByteString
import Data.List (mapAccumL)

gdiffMeta :: GDiffPatch -> [InfoLine]
gdiffMeta patch =
  [ InfoLine "data cmds"   (show dataCount ++ " (" ++ show dataBytes ++ " bytes)")
  , InfoLine "copy cmds"   (show copyCount ++ " (" ++ show copyBytes ++ " bytes)")
  , InfoLine "output size" (show totalOut)
  ]
  where
    commands  = gdiffCommands patch
    dataCount = length [() | GDiffData _ <- commands]
    copyCount = length [() | GDiffCopy{} <- commands]
    dataBytes = sum [ByteString.length payload | GDiffData payload      <- commands]
    copyBytes = sum [unFileSize copyLength     | GDiffCopy _ copyLength <- commands]
    totalOut  = dataBytes + copyBytes

analyzeGDIFF :: GDiffPatch -> PatchAnalysis
analyzeGDIFF patch = PatchAnalysis
  { analysisSections = [SectionRegions (snd (mapAccumL makeGDIFFRegion (Offset 0) (gdiffCommands patch)))]
  , analysisSummary  = Summary (SummaryInfo (Tally commandCount) Commands Nothing)
  }
  where
    commandCount = length (gdiffCommands patch)

makeGDIFFRegion :: Offset -> GDiffCommand -> (Offset, AnalysisRegion)
makeGDIFFRegion outputPosition command = case command of
  GDiffData payload ->
    let payloadLength = byteLength payload
    in ( advance outputPosition payloadLength
       , AnalysisRegion outputPosition payloadLength "DATA  " (PayloadWrite payload)
           (AnnotationAt AtOutput outputPosition [])
       )
  GDiffCopy sourceOffset copyLength ->
    ( advance outputPosition (Length (unFileSize copyLength))
    , AnalysisRegion outputPosition (Length (unFileSize copyLength)) "COPY  " (PayloadCopy FromSource)
        (AnnotationAt AtOutput outputPosition [DetailSource sourceOffset])
    )
