{-# LANGUAGE OverloadedStrings #-}

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
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), renderAsText)
import Slap.Measure (Length(..), Offset(..), advance, byteLength)

import Data.List (mapAccumL)

gdiffMeta :: GDiffPatch -> [InfoLine]
gdiffMeta patch =
  [ InfoLine "data cmds"   (renderAsText dataCount <> " (" <> renderAsText (unLength dataBytes) <> " bytes)")
  , InfoLine "copy cmds"   (renderAsText copyCount <> " (" <> renderAsText (unLength copyBytes) <> " bytes)")
  , InfoLine "output size" (renderAsText (unLength totalOut))
  ]
  where
    commands  = gdiffCommands patch
    dataCount = length [() | GDiffCommandData{} <- commands]
    copyCount = length [() | GDiffCommandCopy{} <- commands]
    dataBytes = mconcat [byteLength payload | GDiffCommandData { gdiffDataPayload = payload } <- commands]
    copyBytes = mconcat [copyLength         | GDiffCommandCopy { gdiffCopyLength = copyLength } <- commands]
    totalOut  = dataBytes <> copyBytes

analyzeGDIFF :: GDiffPatch -> PatchAnalysis
analyzeGDIFF patch = PatchAnalysis
  { analysisSections = [SectionRegions (snd (mapAccumL makeGDIFFRegion (Offset 0) (gdiffCommands patch)))]
  , analysisSummary  = Summary (SummaryInfo (Tally commandCount) Commands Nothing)
  }
  where
    commandCount = length (gdiffCommands patch)

makeGDIFFRegion :: Offset -> GDiffCommand -> (Offset, AnalysisRegion)
makeGDIFFRegion outputPosition command = case command of
  GDiffCommandData { gdiffDataPayload = payload } ->
    let payloadLength = byteLength payload
    in ( advance outputPosition payloadLength
       , AnalysisRegion outputPosition payloadLength "DATA  " (PayloadWrite payload)
           (AnnotationAt AtOutput outputPosition [])
       )
  GDiffCommandCopy { gdiffCopyOffset = sourceOffset, gdiffCopyLength = copyLength } ->
    ( advance outputPosition copyLength
    , AnalysisRegion outputPosition copyLength "COPY  " (PayloadCopy FromSource)
        (AnnotationAt AtOutput outputPosition [DetailSource sourceOffset])
    )
