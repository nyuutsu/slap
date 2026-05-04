module Slap.VCDIFF.Describe
  ( vcdiffMeta
  , analyzeVCDIFF
  , makeVCDIFFSection
  , decodedToRegion
  ) where

import Slap.VCDIFF.Types
    ( VCDIFFPatch(..), VCDIFFHeader(..), VCDIFFWindow(..)
    , VCDIFFDecodedInstruction(..), VCDIFFVersion(..)
    )
import Slap.VCDIFF.Apply (decodeWindowInstructions)
import Slap.Explain
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (showAdler32)
import Slap.Display (InfoLine(..), Tally(..), CountUnit(..), ByteCount(..))
import Slap.Format (padHex)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Delta(..), displace)

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

vcdiffMeta :: VCDIFFPatch -> [InfoLine]
vcdiffMeta patch = concat
  [ [InfoLine "version" (displayVersion (vcdiffVersion (vcdiffHeader patch)))]
  , case vcdiffCompressorId (vcdiffHeader patch) of
      Nothing -> []
      Just compressor  -> [InfoLine "compressor" (show compressor)]
  , if vcdiffHasCodeTable (vcdiffHeader patch)
    then [InfoLine "code table" ("custom (near=" ++ show (vcdiffNearSize patch)
          ++ ", same=" ++ show (vcdiffSameSize patch) ++ ")")]
    else []
  , [InfoLine "target size" (show (sum (map (unFileSize . vcdiffTargetLength) (vcdiffWindows patch))))]
  , if any ((/= Nothing) . vcdiffAdler32) (vcdiffWindows patch)
    then [InfoLine "checksums" "Adler32 (xdelta3)"]
    else []
  ]

displayVersion :: VCDIFFVersion -> String
displayVersion VCDIFFStandard = "0 (standard)"
displayVersion VCDIFFXDelta3  = "0x53 (xdelta3)"

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

analyzeVCDIFF :: VCDIFFPatch -> PatchAnalysis
analyzeVCDIFF patch = PatchAnalysis
  { analysisSections = concat windowSections
  , analysisSummary  = Summary (SummaryInfo (Tally totalInstructions) Instructions
                                  (Just (TotalOutputBytes (FileSize totalTarget))))
  }
  where
    windows = vcdiffWindows patch
    totalTarget = sum (map (unFileSize . vcdiffTargetLength) windows)
    codeTable  = vcdiffCodeTable patch
    nearSize = vcdiffNearSize patch
    sameSize = vcdiffSameSize patch
    decoded    = map (decodeWindowInstructions codeTable nearSize sameSize) windows
    totalInstructions = sum (map length decoded)
    globalOffsets = map Offset (scanl (+) 0 (map (unFileSize . vcdiffTargetLength) windows))
    windowSections = [ makeVCDIFFSection index globalOffset window decodedInstructions
                     | (index, (globalOffset, window, decodedInstructions)) <- zip [1..] (zip3 globalOffsets windows decoded) ]

makeVCDIFFSection :: Int -> Offset -> VCDIFFWindow -> [VCDIFFDecodedInstruction]
                -> [AnalysisSection]
makeVCDIFFSection index globalOffset window instructions =
  [ SectionLabeled ("window " ++ show index ++ ":")
      ( [ InfoLine "target size" (show (unFileSize (vcdiffTargetLength window)))
        , InfoLine "source segment" (show (unFileSize (vcdiffSourceLength window)) ++ " bytes at 0x"
            ++ padHex 6 (unOffset (vcdiffSourcePosition window)))
        , InfoLine "add/run data" (show (ByteString.length (vcdiffAddRunData window)) ++ " bytes")
        , InfoLine "instructions" (show (ByteString.length (vcdiffInstructions window)) ++ " bytes")
        , InfoLine "addresses" (show (ByteString.length (vcdiffAddresses window)) ++ " bytes")
        ] ++ adlerPair
      )
  , SectionRegions (map (decodedToRegion globalOffset) instructions)
  ]
  where
    adlerPair = case vcdiffAdler32 window of
      Nothing      -> []
      Just adler   -> [InfoLine "adler32" ("0x" ++ showAdler32 adler)]

decodedToRegion :: Offset -> VCDIFFDecodedInstruction -> AnalysisRegion
decodedToRegion globalOffset instruction = case instruction of
  DecodedAdd windowOffset payload -> AnalysisRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = Length (ByteString.length payload)
    , regionLabel      = "Add    "
    , regionPayload    = PayloadWrite payload
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) []
    }
  DecodedRun windowOffset fillByte count -> AnalysisRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = count
    , regionLabel      = "Run  "
    , regionPayload    = PayloadFill fillByte count
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) [DetailRLE]
    }
  DecodedCopy windowOffset copySize (Just sourceOffset) -> AnalysisRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = copySize
    , regionLabel      = "Copy   "
    , regionPayload    = PayloadCopy FromSource
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) [DetailSource sourceOffset]
    }
  DecodedCopy windowOffset copySize Nothing -> AnalysisRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = copySize
    , regionLabel      = "Copy   "
    , regionPayload    = PayloadCopy FromTarget
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) []
    }
  where
    absoluteOffset windowOffset = displace globalOffset (Delta (unOffset windowOffset))
