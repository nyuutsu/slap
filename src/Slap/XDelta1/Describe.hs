module Slap.XDelta1.Describe
  ( xdelta1Info
  , xdelta1Meta
  , analyzeXDelta1
  , makeXDelta1Region
  , makeXDelta1SourceText
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..)
    , XDelta1SourceKind(..), XDelta1OffsetMode(..), fromXDelta1Version
    )
import Slap.Explain
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (MD5Hash(..))
import Slap.Display (InfoLine(..), renderInfoLine,
                     Tally(..), CountUnit(..), ByteCount(..))
import Slap.Format (hexByteString)
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
     , InfoLine "sources" (show (length sources))
     ]
  ++ sourceMD5s
  ++ [ InfoLine "data seg" (show (ByteString.length (xdelta1DataSegment patch)) ++ " bytes") ]
  where
    sources = xdelta1Sources patch
    sourceMD5s
      | [entry] <- sources = [InfoLine "source MD5" (hexByteString (unMD5Hash (xdelta1SourceMD5 entry)))]
      | otherwise       = [InfoLine ("source " ++ show index ++ " MD5") (hexByteString (unMD5Hash (xdelta1SourceMD5 entry)))
                            | (index, entry) <- zip [(1::Int)..] sources]

xdelta1Info :: XDelta1Patch -> String
xdelta1Info patch = unlines $ filter (not . null) $
  [ "format:      xdelta1 v" ++ fromXDelta1Version (xdelta1Version patch) ]
  ++ map renderInfoLine (xdelta1Meta patch)
  ++ [ sourceLines
     , "instructions:" ++ show (length (xdelta1Instructions patch))
     ]
  where
    sourceLines = unlines
      [ "  [" ++ show index ++ "] " ++ decodeLocaleField (xdelta1SourceName entry)
        ++ (case xdelta1SourceKind entry of DataSegmentSource -> " (data)"; FileSource -> " (file)")
        ++ (case xdelta1SourceOffsetMode entry of SequentialOffsets -> " seq"; AbsoluteOffsets -> "")
        ++ "  " ++ show (unFileSize (xdelta1SourceLength entry)) ++ " bytes"
        ++ "  MD5:" ++ hexByteString (unMD5Hash (xdelta1SourceMD5 entry))
      | (index, entry) <- zip [(0::Int)..] (xdelta1Sources patch) ]

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

analyzeXDelta1 :: XDelta1Patch -> PatchAnalysis
analyzeXDelta1 patch = PatchAnalysis
  { analysisSections = map makeXDelta1SourceText (zip [0..] (xdelta1Sources patch))
      ++ [SectionText "", SectionText ("instructions: " ++ show instructionCount), SectionText ""]
      ++ [SectionRegions (map makeXDelta1Region (xdelta1Instructions patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally instructionCount) Instructions (Just (TotalOutputBytes (xdelta1TargetLength patch))))
  }
  where
    instructionCount = length (xdelta1Instructions patch)

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
  , regionAnnotation = AnnotAt AtOffset (xdelta1InstructionOffset instruction)
      [DetailSourceIndex (xdelta1InstructionIndex instruction)]
  }
