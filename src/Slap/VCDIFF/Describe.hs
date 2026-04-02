module Slap.VCDIFF.Describe
  ( vcdiffInfo
  , vcdiffMeta
  , explainVCDIFF
  , makeVCDIFFSection
  , decodedToRegion
  ) where

import Slap.VCDIFF.Types
    ( VCDIFFPatch(..), VCDIFFHeader(..), VCDIFFWindow(..)
    , VCDIFFDecodedInstruction(..)
    )
import Slap.VCDIFF.Apply (decodeWindowInstructions)
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), CopySource(..), ExplainSummary(..)
    , SummaryBytes(..), Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (Adler32(..), showAdler32)
import Slap.Format (padHex, renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..))

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

vcdiffMeta :: VCDIFFPatch -> [(String, String)]
vcdiffMeta patch = concat
  [ [("version", show (vcdiffVersion (vcdiffHeader patch)))]
  , case vcdiffCompressorId (vcdiffHeader patch) of
      Nothing -> []
      Just compressor  -> [("compressor", show compressor)]
  , if vcdiffHasCodeTable (vcdiffHeader patch)
    then [("code table", "custom (near=" ++ show (vcdiffNearSize patch)
          ++ ", same=" ++ show (vcdiffSameSize patch) ++ ")")]
    else []
  , [("target size", show (sum (map (unFileSize . vcdiffTargetLength) (vcdiffWindows patch))))]
  , if any ((/= Nothing) . vcdiffAdler32) (vcdiffWindows patch)
    then [("checksums", "Adler32 (xdelta3)")]
    else []
  ]

vcdiffInfo :: VCDIFFPatch -> String
vcdiffInfo patch = unlines $ filter (not . null) $
  [ "format:      VCDIFF" ++ if vcdiffVersion (vcdiffHeader patch) == 0x53
                              then " (xdelta3)" else "" ]
  ++ map renderField (vcdiffMeta patch)
  ++ [ "windows:     " ++ show (length (vcdiffWindows patch)) ]

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainVCDIFF :: VCDIFFPatch -> ExplainData
explainVCDIFF patch = ExplainData
  { explainFormat   = "VCDIFF" ++ if vcdiffVersion (vcdiffHeader patch) == 0x53
                               then " (xdelta3)" else ""
  , explainHeader   = vcdiffMeta patch
  , explainSections = concat windowSections
  , explainSummary  = Summary totalInstructions "instructions"
                   (Just (fromIntegral totalTarget, BytesTotalOutput))
  , explainNotes    = []
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
                -> [ExplainSection]
makeVCDIFFSection index globalOffset window instructions =
  [ SectionLabeled ("window " ++ show index ++ ":")
      ( [ ("target size", show (unFileSize (vcdiffTargetLength window)))
        , ("source segment", show (unFileSize (vcdiffSourceLength window)) ++ " bytes at 0x"
            ++ padHex 6 (unOffset (vcdiffSourcePosition window)))
        , ("add/run data", show (ByteString.length (vcdiffAddRunData window)) ++ " bytes")
        , ("instructions", show (ByteString.length (vcdiffInstructions window)) ++ " bytes")
        , ("addresses", show (ByteString.length (vcdiffAddresses window)) ++ " bytes")
        ] ++ adlerPair
      )
  , SectionRegions (map (decodedToRegion globalOffset) instructions)
  ]
  where
    adlerPair = case vcdiffAdler32 window of
      Nothing      -> []
      Just adler   -> [("adler32", "0x" ++ showAdler32 adler)]

decodedToRegion :: Offset -> VCDIFFDecodedInstruction -> ExplainRegion
decodedToRegion globalOffset instruction = case instruction of
  DecodedAdd windowOffset payload -> ExplainRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = Length (ByteString.length payload)
    , regionLabel      = "Add    "
    , regionPayload    = PayloadWrite payload
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) []
    }
  DecodedRun windowOffset fillByte count -> ExplainRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = Length count
    , regionLabel      = "Run  "
    , regionPayload    = PayloadFill fillByte count
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) [DetailRLE]
    }
  DecodedCopy windowOffset copySize (Just sourceOffset) -> ExplainRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = Length copySize
    , regionLabel      = "Copy   "
    , regionPayload    = PayloadCopy FromSource
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) [DetailSource (Offset sourceOffset)]
    }
  DecodedCopy windowOffset copySize Nothing -> ExplainRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = Length copySize
    , regionLabel      = "Copy   "
    , regionPayload    = PayloadCopy FromTarget
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) []
    }
  where
    absoluteOffset windowOffset = Offset (unOffset globalOffset + windowOffset)
