module Slap.XDelta1.Describe
  ( xdelta1Meta
  , analyzeXDelta1
  , makeXDelta1Region
  , makeXDelta1SourceText
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..)
    , XDelta1SourceKind(..), XDelta1OffsetMode(..), XDelta1SourceShape(..)
    , fromXDelta1Version
    )
import Slap.Display.Analysis
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (MD5Hash(..))
import Slap.Display.Common (InfoLine(..),
                     Tally(..), CountUnit(..), ByteCount(..))
import Slap.Display.Primitives (hexByteString)
import Slap.Measure (Length(..), FileSize(..))

import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

xdelta1Meta :: XDelta1Patch -> [InfoLine]
xdelta1Meta patch =
  [ InfoLine "version" (fromXDelta1Version (xdelta1Version patch)) ]
  ++ [ InfoLine "from" (decodeLocaleField (xdelta1FromName patch))
     , InfoLine "to" (decodeLocaleField (xdelta1ToName patch))
     , InfoLine "target size" (show (unFileSize (xdelta1TargetLength patch)))
     , InfoLine "target MD5" (hexByteString (unMD5Hash (xdelta1ToMD5 patch)))
     , InfoLine "sources" (show (length indexedSources))
     ]
  ++ sourceMD5s
  ++ [ InfoLine "data seg" (show (ByteString.length (xdelta1DataSegment patch)) ++ " bytes") ]
  where
    indexedSources = shapeSourcesIndexed (xdelta1SourceShape patch)
    sourceMD5s = case indexedSources of
      [(_, single)]
        -> [InfoLine "source MD5" (hexByteString (unMD5Hash (xdelta1SourceMD5 single)))]
      manySources
        -> [ InfoLine ("source " ++ show rank ++ " MD5")
                      (hexByteString (unMD5Hash (xdelta1SourceMD5 entry)))
           | (rank, (_, entry)) <- zip [(1::Int)..] manySources
           ]

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

analyzeXDelta1 :: XDelta1Patch -> PatchAnalysis
analyzeXDelta1 patch = PatchAnalysis
  { analysisSections = map makeXDelta1SourceText (shapeSourcesIndexed (xdelta1SourceShape patch))
      ++ [SectionText "", SectionText ("instructions: " ++ show instructionCount), SectionText ""]
      ++ [SectionRegions (map makeXDelta1Region (xdelta1Instructions patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally instructionCount) Instructions (Just (TotalOutputBytes (xdelta1TargetLength patch))))
  }
  where
    instructionCount = length (xdelta1Instructions patch)

-- | Walk an 'XDelta1SourceShape' as an indexed list of its sources,
-- preserving the wire-format index that 'XDelta1Instruction'
-- references. Total over all four shape constructors.
shapeSourcesIndexed :: XDelta1SourceShape -> [(Int, XDelta1Source)]
shapeSourcesIndexed XDelta1NoSources                       = []
shapeSourcesIndexed (XDelta1DataOnly source)               = [(0, source)]
shapeSourcesIndexed (XDelta1FileOnly source)               = [(0, source)]
shapeSourcesIndexed (XDelta1DataAndFile dataSrc fileSrc)   = [(0, dataSrc), (1, fileSrc)]

makeXDelta1SourceText :: (Int, XDelta1Source) -> AnalysisSection
makeXDelta1SourceText (index, sourceEntry) = SectionText $
  "  [" ++ show index ++ "] " ++ decodeLocaleField (xdelta1SourceName sourceEntry)
  ++ (case xdelta1SourceKind sourceEntry of DataSegmentSource -> " (data)"; FileSource -> " (file)")
  ++ (case xdelta1SourceOffsetMode sourceEntry of SequentialOffsets -> " seq"; AbsoluteOffsets -> "")
  ++ "  " ++ show (unFileSize (xdelta1SourceLength sourceEntry)) ++ " bytes"
  ++ "  MD5:" ++ hexByteString (unMD5Hash (xdelta1SourceMD5 sourceEntry))

makeXDelta1Region :: XDelta1Instruction -> AnalysisRegion
makeXDelta1Region instruction = AnalysisRegion
  { regionOffset     = xdelta1InstructionOffset instruction
  , regionSize       = Length (unFileSize (xdelta1InstructionLength instruction))
  , regionLabel      = "Copy  "
  , regionPayload    = PayloadCopy FromSource
  , regionAnnotation = AnnotationAt AtOffset (xdelta1InstructionOffset instruction)
      [DetailSourceIndex (xdelta1InstructionIndex instruction)]
  }
