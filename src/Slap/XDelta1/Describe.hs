{-# LANGUAGE OverloadedStrings #-}

module Slap.XDelta1.Describe
  ( xdelta1Meta
  , analyzeXDelta1
  , makeXDelta1Region
  , makeXDelta1DataRecordText
  , makeXDelta1FileSourceText
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Instruction(..)
    , XDelta1InstructionTarget(..)
    , XDelta1OffsetMode(..)
    , XDelta1VerificationPosture(..)
    , XDelta1FileAtDeltaTime(..)
    , xdelta1DataRecordName
    )
import Slap.Display.Analysis
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Binary (md5)
import Slap.Checksum (MD5Hash(..))
import Slap.Display.Common (InfoLine(..),
                     Tally(..), CountUnit(..), ByteCount(..))
import Slap.Display.Primitives (hexByteString)
import Slap.Measure (Length(..), FileSize(..))

import Slap.TextEncoding (decodeLocaleField)

import Data.Int (Int64)
import Data.ByteString (ByteString)
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
  [ InfoLine "data seg"    (show dataSegmentLength ++ " bytes") ]
  where
    dataSegmentLength = ByteString.length (xdelta1DataSegment patch)

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
        [ InfoLine "data segment MD5"
            (hexByteString (unMD5Hash (md5 (xdelta1DataSegment patch))))
        ]
        ++ case xdelta1SourceMD5 patch of
             Just fileMD5 -> [InfoLine "file source MD5" (hexByteString (unMD5Hash fileMD5))]
             Nothing      -> []

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

analyzeXDelta1 :: XDelta1Patch -> PatchAnalysis
analyzeXDelta1 patch = PatchAnalysis
  { analysisSections =
      [ makeXDelta1DataRecordText patch
      , makeXDelta1FileSourceText patch
      , SectionText ""
      , SectionText ("instructions: " ++ show instructionCount)
      , SectionText ""
      , SectionRegions (map makeXDelta1Region (xdelta1Instructions patch))
      ]
  , analysisSummary  = Summary (SummaryInfo (Tally instructionCount) Instructions (Just (TotalOutputBytes (xdelta1TargetLength patch))))
  }
  where
    instructionCount = length (xdelta1Instructions patch)

-- | Render the data-record source section as the encoder would have
-- written it: name is 'xdelta1DataRecordName', length is the data
-- segment's byte count, offset-mode is always sequential, MD5 is the
-- segment-bytes MD5 (only when the patch's posture is
-- 'VerifyAgainstStoredMD5s'). The format mirrors
-- 'makeXDelta1FileSourceText' so explain output reads as two
-- comparable rows.
makeXDelta1DataRecordText :: XDelta1Patch -> AnalysisSection
makeXDelta1DataRecordText patch =
  renderSourceLine 0 "data" xdelta1DataRecordName
    (FileSize dataSegmentLength) SequentialOffsets dataMD5
  where
    dataSegmentBytes  = xdelta1DataSegment patch
    dataSegmentLength = ByteString.length dataSegmentBytes
    dataMD5 = case xdelta1Verification patch of
      VerifyAgainstStoredMD5s _     -> Just (md5 dataSegmentBytes)
      CreatorOptedOutOfVerification -> Nothing

-- | Render the file-source section from the patch's flat
-- @xdelta1Source*@ fields.
makeXDelta1FileSourceText :: XDelta1Patch -> AnalysisSection
makeXDelta1FileSourceText patch =
  renderSourceLine 1 "file"
    (xdelta1SourceName patch)
    (xdelta1SourceLength patch)
    (xdelta1SourceOffsetMode patch)
    (xdelta1SourceMD5 patch)

renderSourceLine
  :: Int -> String -> ByteString -> FileSize -> XDelta1OffsetMode
  -> Maybe MD5Hash -> AnalysisSection
renderSourceLine index kindLabel sourceName sourceLength offsetMode md5Hash = SectionText $
  "  [" ++ show index ++ "] " ++ decodeLocaleField sourceName
  ++ " (" ++ kindLabel ++ ")"
  ++ (case offsetMode of SequentialOffsets -> " seq"; AbsoluteOffsets -> "")
  ++ "  " ++ show (unFileSize sourceLength) ++ " bytes"
  ++ (case md5Hash of
        Just hash -> "  MD5:" ++ hexByteString (unMD5Hash hash)
        Nothing   -> "")

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
