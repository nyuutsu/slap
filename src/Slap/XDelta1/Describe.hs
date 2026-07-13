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
    , XDelta1SourceRoster(..), XDelta1FileSource(..)
    , rosterFileSource, rosterSourceCount, instructionTargetWireIndex
    , XDelta1OffsetMode(..)
    , XDelta1VerificationPosture(..)
    , XDelta1FileAtDeltaTime(..)
    , XDelta1FromName(..)
    , XDelta1ToName(..)
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
                     Tally(..), CountUnit(..), ByteCount(..), renderAsText)
import Slap.Display.Primitives (hexByteString)
import Slap.Measure (Length(..), FileSize(..))
import Slap.Text (EncodedText(..), EncodingName(..), encodedTextContent)

import Data.Text (Text)
import qualified Data.ByteString as ByteString
import qualified Data.Text.Encoding as TextEncoding

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

xdelta1Meta :: XDelta1Patch -> [InfoLine]
xdelta1Meta patch =
  [ InfoLine "from"        (renderName (unXDelta1FromName (xdelta1FromName patch)))
  , InfoLine "to"          (renderName (unXDelta1ToName   (xdelta1ToName   patch)))
  , InfoLine "target size" (renderAsText (unFileSize (xdelta1TargetLength patch)))
  ] ++ verificationLines ++ inputsLines ++
  [ InfoLine "sources"     (renderAsText (rosterSourceCount roster))
  ] ++ sourceMD5Lines ++
  [ InfoLine "data seg"    (renderAsText dataSegmentLength <> " bytes") ]
  where
    roster            = xdelta1SourceRoster patch
    dataSegmentLength = ByteString.length (xdelta1DataSegment patch)

    rosterCarriesDataRecord = case roster of
      DataAndFileSources _ -> True
      DataSourceOnly       -> True
      FileSourceOnly _     -> False
      NoSources            -> False

    verificationLines = case xdelta1Verification patch of
      VerifyAgainstStoredMD5s targetMD5
        -> [InfoLine "target MD5"   (hexByteString (unMD5Hash targetMD5))]
      CreatorOptedOutOfVerification
        -> [InfoLine "verification" "opted out by creator (--no-verify)"]

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
        | rosterCarriesDataRecord ]
        ++ case rosterFileSource roster >>= xdelta1FileSourceMD5 of
             Just fileMD5 -> [InfoLine "file source MD5" (hexByteString (unMD5Hash fileMD5))]
             Nothing      -> []

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

analyzeXDelta1 :: XDelta1Patch -> PatchAnalysis
analyzeXDelta1 patch = PatchAnalysis
  { analysisSections =
      sourceRowSections ++
      [ SectionText ""
      , SectionText ("instructions: " <> renderAsText instructionCount)
      , SectionText ""
      , SectionRegions (map (makeXDelta1Region roster) (xdelta1Instructions patch))
      ]
  , analysisSummary  = Summary (SummaryInfo (Tally instructionCount) Instructions (Just (TotalOutputBytes (xdelta1TargetLength patch))))
  }
  where
    instructionCount = length (xdelta1Instructions patch)
    roster           = xdelta1SourceRoster patch

    sourceRowSections = case roster of
      DataAndFileSources fileSource ->
        [ makeXDelta1DataRecordText 0 patch
        , makeXDelta1FileSourceText 1 fileSource
        ]
      DataSourceOnly                -> [makeXDelta1DataRecordText 0 patch]
      FileSourceOnly fileSource     -> [makeXDelta1FileSourceText 0 fileSource]
      NoSources                     -> [SectionText "  (no sources; the declared target is empty)"]

-- | Render the data-record's row for the analysis, re-derived rather than stored.
-- 'xdelta1DataRecordName' is a fixed ASCII constant (@"(patch data)"@), byte-identical under UTF-8,
-- so tagging it 'EncodingUtf8' is accurate and lets it share 'renderSourceLine' with the file-source row.
makeXDelta1DataRecordText :: Int -> XDelta1Patch -> AnalysisSection
makeXDelta1DataRecordText listIndex patch =
  renderSourceLine listIndex "data" dataRecordNameText
    (FileSize (fromIntegral dataSegmentLength)) SequentialOffsets dataMD5
  where
    dataRecordNameText =
      EncodedText EncodingUtf8 (TextEncoding.decodeUtf8 xdelta1DataRecordName)
    dataSegmentBytes  = xdelta1DataSegment patch
    dataSegmentLength = ByteString.length dataSegmentBytes
    dataMD5 = case xdelta1Verification patch of
      VerifyAgainstStoredMD5s _     -> Just (md5 dataSegmentBytes)
      CreatorOptedOutOfVerification -> Nothing

makeXDelta1FileSourceText :: Int -> XDelta1FileSource -> AnalysisSection
makeXDelta1FileSourceText listIndex fileSource =
  renderSourceLine listIndex "file"
    (unXDelta1FromName (xdelta1FileSourceName fileSource))
    (xdelta1FileSourceLength fileSource)
    (xdelta1FileSourceOffsetMode fileSource)
    (xdelta1FileSourceMD5 fileSource)

renderSourceLine
  :: Int -> Text -> EncodedText -> FileSize -> XDelta1OffsetMode
  -> Maybe MD5Hash -> AnalysisSection
renderSourceLine listIndex kindLabel sourceName sourceLength offsetMode md5Hash = SectionText $
  "  [" <> renderAsText listIndex <> "] " <> renderName sourceName
  <> " (" <> kindLabel <> ")"
  <> (case offsetMode of SequentialOffsets -> " seq"; AbsoluteOffsets -> "")
  <> "  " <> renderAsText (unFileSize sourceLength) <> " bytes"
  <> (case md5Hash of
        Just hash -> "  MD5:" <> hexByteString (unMD5Hash hash)
        Nothing   -> "")

-- | Render an 'EncodedText'-shaped xdelta1 name as 'Text' for the
-- info-line lane. The decoded codepoints come straight off the typed
-- field; no per-call locale decode is needed.
renderName :: EncodedText -> Text
renderName = encodedTextContent

makeXDelta1Region :: XDelta1SourceRoster -> XDelta1Instruction -> AnalysisRegion
makeXDelta1Region roster instruction = AnalysisRegion
  { regionOffset     = xdelta1InstructionOffset instruction
  , regionSize       = Length (unFileSize (xdelta1InstructionLength instruction))
  , regionLabel      = "Copy  "
  , regionPayload    = PayloadCopy FromSource
  , regionAnnotation = AnnotationAt AtOffset (xdelta1InstructionOffset instruction)
      [DetailSourceIndex (fromIntegral (instructionTargetWireIndex roster (xdelta1InstructionTarget instruction)))]
  }
