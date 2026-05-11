module Slap.XDelta1.Describe
  ( xdelta1Meta
  , analyzeXDelta1
  , makeXDelta1Region
  , makeXDelta1SourceText
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..)
    , XDelta1SourceKind(..), XDelta1OffsetMode(..), XDelta1SourceShape(..)
    , XDelta1VerificationPosture(..)
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
  [ InfoLine "from"        (decodeLocaleField (xdelta1FromName patch))
  , InfoLine "to"          (decodeLocaleField (xdelta1ToName patch))
  , InfoLine "target size" (show (unFileSize (xdelta1TargetLength patch)))
  ] ++ verificationLines ++
  [ InfoLine "sources"     (show sourceCount)
  ] ++ sourceMD5Lines ++
  [ InfoLine "data seg"    (show (ByteString.length (xdelta1DataSegment patch)) ++ " bytes") ]
  where
    sourceCount = case xdelta1SourceShape patch of
      XDelta1NoSources       -> 0 :: Int
      XDelta1DataOnly _      -> 1
      XDelta1FileOnly _      -> 1
      XDelta1DataAndFile _ _ -> 2

    verificationLines = case xdelta1Verification patch of
      VerifyAgainstStoredMD5s targetMD5
        -> [InfoLine "target MD5"   (hexByteString (unMD5Hash targetMD5))]
      CreatorOptedOutOfVerification
        -> [InfoLine "verification" "opted out by creator (--no-verify)"]

    sourceMD5Lines = case xdelta1Verification patch of
      CreatorOptedOutOfVerification -> []
      VerifyAgainstStoredMD5s _     -> case xdelta1SourceShape patch of
        XDelta1NoSources                   -> []
        XDelta1DataOnly source             -> md5LineFor "data segment MD5" source
        XDelta1FileOnly source             -> md5LineFor "file source MD5"  source
        XDelta1DataAndFile dataSrc fileSrc ->
          md5LineFor "data segment MD5" dataSrc
          ++ md5LineFor "file source MD5"  fileSrc

    md5LineFor :: String -> XDelta1Source -> [InfoLine]
    md5LineFor label src = case xdelta1SourceMD5 src of
      Just md5 -> [InfoLine label (hexByteString (unMD5Hash md5))]
      Nothing  -> []

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
  ++ (case xdelta1SourceMD5 sourceEntry of
        Just md5 -> "  MD5:" ++ hexByteString (unMD5Hash md5)
        Nothing  -> "")

makeXDelta1Region :: XDelta1Instruction -> AnalysisRegion
makeXDelta1Region instruction = AnalysisRegion
  { regionOffset     = xdelta1InstructionOffset instruction
  , regionSize       = Length (unFileSize (xdelta1InstructionLength instruction))
  , regionLabel      = "Copy  "
  , regionPayload    = PayloadCopy FromSource
  , regionAnnotation = AnnotationAt AtOffset (xdelta1InstructionOffset instruction)
      [DetailSourceIndex (xdelta1InstructionIndex instruction)]
  }
