module Slap.XDelta1.Describe
  ( xdelta1Meta
  , analyzeXDelta1
  , makeXDelta1Region
  , makeXDelta1SourceText
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..)
    , XDelta1Sources(..)
    , XDelta1InstructionTarget(..)
    , XDelta1OffsetMode(..)
    , XDelta1VerificationPosture(..)
    , XDelta1FileAtDeltaTime(..)
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

import Data.Int (Int64)
import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

xdelta1Meta :: XDelta1Patch -> [InfoLine]
xdelta1Meta patch =
  [ InfoLine "from"        (decodeLocaleField (xdelta1FromName patch))
  , InfoLine "to"          (decodeLocaleField (xdelta1ToName patch))
  , InfoLine "target size" (show (unFileSize (xdelta1TargetLength patch)))
  ] ++ verificationLines ++ inputsLines ++
  [ InfoLine "sources"     "2"
  ] ++ sourceMD5Lines ++
  [ InfoLine "data seg"    (show (ByteString.length (xdelta1DataSegment patch)) ++ " bytes") ]
  where
    sources = xdelta1Sources patch

    verificationLines = case xdelta1Verification patch of
      VerifyAgainstStoredMD5s targetMD5
        -> [InfoLine "target MD5"   (hexByteString (unMD5Hash targetMD5))]
      CreatorOptedOutOfVerification
        -> [InfoLine "verification" "opted out by creator (--no-verify)"]

    -- Bits 1 and 2 of the header's flags word. Common case (both
    -- raw bytes) shows nothing — info stays uncluttered. When at
    -- least one side is a gzip stream, surface a single descriptive
    -- line naming the affected side(s) and the relevant flag bit(s),
    -- and remind the reader that apply will refuse on this patch.
    inputsLines = case (xdelta1FromAtDeltaTime patch, xdelta1ToAtDeltaTime patch) of
      (FileWasRawBytes,   FileWasRawBytes)   -> []
      (FileWasGzipStream, FileWasRawBytes)
        -> [InfoLine "inputs" "from-file expected gzipped at apply time (FROM_COMPRESSED set; slap refuses apply)"]
      (FileWasRawBytes,   FileWasGzipStream)
        -> [InfoLine "inputs" "to-file expected gzipped at apply time (TO_COMPRESSED set; slap refuses apply)"]
      (FileWasGzipStream, FileWasGzipStream)
        -> [InfoLine "inputs" "both expected gzipped at apply time (FROM_COMPRESSED+TO_COMPRESSED set; slap refuses apply)"]

    sourceMD5Lines = case xdelta1Verification patch of
      CreatorOptedOutOfVerification -> []
      VerifyAgainstStoredMD5s _     ->
        md5LineFor "data segment MD5" (xdelta1DataSource sources)
        ++ md5LineFor "file source MD5" (xdelta1FileSource sources)

    md5LineFor :: String -> XDelta1Source -> [InfoLine]
    md5LineFor label src = case xdelta1SourceMD5 src of
      Just md5 -> [InfoLine label (hexByteString (unMD5Hash md5))]
      Nothing  -> []

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

analyzeXDelta1 :: XDelta1Patch -> PatchAnalysis
analyzeXDelta1 patch = PatchAnalysis
  { analysisSections =
      [ makeXDelta1SourceText 0 "data" (xdelta1DataSource sources)
      , makeXDelta1SourceText 1 "file" (xdelta1FileSource sources)
      , SectionText ""
      , SectionText ("instructions: " ++ show instructionCount)
      , SectionText ""
      , SectionRegions (map makeXDelta1Region (xdelta1Instructions patch))
      ]
  , analysisSummary  = Summary (SummaryInfo (Tally instructionCount) Instructions (Just (TotalOutputBytes (xdelta1TargetLength patch))))
  }
  where
    sources = xdelta1Sources patch
    instructionCount = length (xdelta1Instructions patch)

makeXDelta1SourceText :: Int -> String -> XDelta1Source -> AnalysisSection
makeXDelta1SourceText index kindLabel sourceEntry = SectionText $
  "  [" ++ show index ++ "] " ++ decodeLocaleField (xdelta1SourceName sourceEntry)
  ++ " (" ++ kindLabel ++ ")"
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
      [DetailSourceIndex (targetToWireIndex (xdelta1InstructionTarget instruction))]
  }

-- | The wire-format integer that encodes an 'XDelta1InstructionTarget'.
-- Matches what canonical xdelta emits: 0 for the data source, 1 for
-- the file source. Used to keep the explain output's
-- "instruction at offset N references source 0/1" reading intact
-- after the apply-side dispatch was retyped off raw indices.
targetToWireIndex :: XDelta1InstructionTarget -> Int64
targetToWireIndex FromDataSource = 0
targetToWireIndex FromFileSource = 1
