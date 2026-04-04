module Slap.XDelta1.Describe
  ( xdelta1Info
  , xdelta1Meta
  , explainXDelta1
  , makeXDelta1Region
  , makeXDelta1SourceText
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..)
    , XDelta1SourceKind(..), XDelta1OffsetMode(..), fromXDelta1Version
    )
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), CopySource(..), ExplainSummary(..)
    , SummaryInfo(..), SummaryByteInfo(..), SummaryBytes(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (MD5Hash(..))
import Slap.Format (MetaField(..), hexByteString, renderField)
import Slap.Measure (Length(..), FileSize(..))

import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

xdelta1Meta :: XDelta1Patch -> [MetaField]
xdelta1Meta patch =
  [ MetaField "version" (fromXDelta1Version (xdelta1Version patch)) ]
  ++ [ MetaField "from" (decodeLocaleField (xdelta1FromName patch))
     , MetaField "to" (decodeLocaleField (xdelta1ToName patch))
     , MetaField "target size" (show (unFileSize (xdelta1TargetLength patch)))
     , MetaField "target MD5" (hexByteString (unMD5Hash (xdelta1ToMD5 patch)))
     , MetaField "sources" (show (length sources))
     ]
  ++ sourceMD5s
  ++ [ MetaField "data seg" (show (ByteString.length (xdelta1DataSegment patch)) ++ " bytes") ]
  where
    sources = xdelta1Sources patch
    sourceMD5s
      | [entry] <- sources = [MetaField "source MD5" (hexByteString (unMD5Hash (xdelta1SourceMD5 entry)))]
      | otherwise       = [MetaField ("source " ++ show index ++ " MD5") (hexByteString (unMD5Hash (xdelta1SourceMD5 entry)))
                            | (index, entry) <- zip [(1::Int)..] sources]

xdelta1Info :: XDelta1Patch -> String
xdelta1Info patch = unlines $ filter (not . null) $
  [ "format:      xdelta1 v" ++ fromXDelta1Version (xdelta1Version patch) ]
  ++ map renderField (xdelta1Meta patch)
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

explainXDelta1 :: XDelta1Patch -> ExplainData
explainXDelta1 patch = ExplainData
  { explainFormat   = "xdelta1 v" ++ fromXDelta1Version (xdelta1Version patch)
  , explainHeader   = xdelta1Meta patch
  , explainSections = map makeXDelta1SourceText (zip [0..] (xdelta1Sources patch))
      ++ [SectionText "", SectionText ("instructions: " ++ show instructionCount), SectionText ""]
      ++ [SectionRegions (map makeXDelta1Region (xdelta1Instructions patch))]
  , explainSummary  = Summary (SummaryInfo instructionCount "instructions" (Just (SummaryByteInfo (fromIntegral (unFileSize (xdelta1TargetLength patch))) BytesTotalOutput)))
  , explainNotes    = []
  }
  where
    instructionCount = length (xdelta1Instructions patch)

makeXDelta1SourceText :: (Int, XDelta1Source) -> ExplainSection
makeXDelta1SourceText (index, sourceEntry) = SectionText $
  "  [" ++ show index ++ "] " ++ decodeLocaleField (xdelta1SourceName sourceEntry)
  ++ (case xdelta1SourceKind sourceEntry of DataSegmentSource -> " (data)"; FileSource -> " (file)")
  ++ (case xdelta1SourceOffsetMode sourceEntry of SequentialOffsets -> " seq"; AbsoluteOffsets -> "")
  ++ "  " ++ show (unFileSize (xdelta1SourceLength sourceEntry)) ++ " bytes"
  ++ "  MD5:" ++ hexByteString (unMD5Hash (xdelta1SourceMD5 sourceEntry))

makeXDelta1Region :: XDelta1Instruction -> ExplainRegion
makeXDelta1Region instruction = ExplainRegion
  { regionOffset     = xdelta1InstructionOffset instruction
  , regionSize       = Length (fromIntegral (unFileSize (xdelta1InstructionLength instruction)))
  , regionLabel      = "Copy  "
  , regionPayload    = PayloadCopy FromSource
  , regionAnnotation = AnnotAt AtOffset (xdelta1InstructionOffset instruction)
      [DetailSourceIndex (xdelta1InstructionIndex instruction)]
  }
