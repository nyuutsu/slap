module Slap.GDIFF.Describe
  ( gdiffInfo
  , gdiffMeta
  , explainGDIFF
  , makeGDIFFRegion
  ) where

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..))
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), CopySource(..), ExplainSummary(..)
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

explainGDIFF :: GDiffPatch -> ExplainData
explainGDIFF patch = ExplainData
  { explainFormat   = "GDIFF (W3C)"
  , explainHeader   = gdiffMeta patch
  , explainSections = [SectionRegions (snd (mapAccumL makeGDIFFRegion (Offset 0) (gdiffCommands patch)))]
  , explainSummary  = Summary (SummaryInfo commandCount "commands" Nothing)
  , explainNotes    = []
  }
  where
    commandCount = length (gdiffCommands patch)

makeGDIFFRegion :: Offset -> GDiffCommand -> (Offset, ExplainRegion)
makeGDIFFRegion outputPosition command = case command of
  GDiffData payload ->
    let payloadLength = byteLength payload
    in ( advance outputPosition payloadLength
       , ExplainRegion outputPosition payloadLength "DATA  " (PayloadWrite payload)
           (AnnotAt AtOutput outputPosition [])
       )
  GDiffCopy sourceOffset copyLength ->
    ( advance outputPosition (Length (unFileSize copyLength))
    , ExplainRegion outputPosition (Length (unFileSize copyLength)) "COPY  " (PayloadCopy FromSource)
        (AnnotAt AtOutput outputPosition [DetailSource sourceOffset])
    )
