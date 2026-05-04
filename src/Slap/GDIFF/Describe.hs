module Slap.GDIFF.Describe
  ( gdiffInfo
  , gdiffMeta
  , analyzeGDIFF
  , makeGDIFFRegion
  ) where

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..))
import Slap.Explain
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..), Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Display (InfoLine)
import Slap.Measure (Offset(..), Length(..), FileSize(..), advance, byteLength)

import qualified Data.ByteString as ByteString
import Data.List (mapAccumL)

-- | GDIFF carries no header metadata; this returns an empty list.
gdiffMeta :: GDiffPatch -> [InfoLine]
gdiffMeta _ = []

gdiffInfo :: GDiffPatch -> String
gdiffInfo patch = unlines $ filter (not . null)
  [ "format:      GDIFF (W3C)"
  , "commands:    " ++ show commandCount
  , "data cmds:   " ++ show dataCount ++ " (" ++ show dataBytes ++ " bytes)"
  , "copy cmds:   " ++ show copyCount ++ " (" ++ show copyBytes ++ " bytes)"
  , "output size: " ++ show totalOut
  ]
  where
    commands = gdiffCommands patch
    commandCount = length commands
    dataCount = length [() | GDiffData _ <- commands]
    copyCount = length [() | GDiffCopy{} <- commands]
    dataBytes = sum [ByteString.length payload | GDiffData payload      <- commands]
    copyBytes = sum [unFileSize copyLength     | GDiffCopy _ copyLength <- commands]
    totalOut  = dataBytes + copyBytes

analyzeGDIFF :: GDiffPatch -> PatchAnalysis
analyzeGDIFF patch = PatchAnalysis
  { analysisSections = [SectionRegions (snd (mapAccumL makeGDIFFRegion (Offset 0) (gdiffCommands patch)))]
  , analysisSummary  = Summary (SummaryInfo commandCount "commands" Nothing)
  }
  where
    commandCount = length (gdiffCommands patch)

makeGDIFFRegion :: Offset -> GDiffCommand -> (Offset, AnalysisRegion)
makeGDIFFRegion outputPosition command = case command of
  GDiffData payload ->
    let payloadLength = byteLength payload
    in ( advance outputPosition payloadLength
       , AnalysisRegion outputPosition payloadLength "DATA  " (PayloadWrite payload)
           (AnnotAt AtOutput outputPosition [])
       )
  GDiffCopy sourceOffset copyLength ->
    ( advance outputPosition (Length (unFileSize copyLength))
    , AnalysisRegion outputPosition (Length (unFileSize copyLength)) "COPY  " (PayloadCopy FromSource)
        (AnnotAt AtOutput outputPosition [DetailSource sourceOffset])
    )
