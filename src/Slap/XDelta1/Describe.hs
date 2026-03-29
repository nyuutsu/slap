module Slap.XDelta1.Describe
  ( xdelta1Info
  , xdelta1Meta
  , explainXDelta1
  , makeXDelta1Region
  , makeXDelta1SourceText
  ) where

import Slap.XDelta1.Types (XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..))
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), CopySource(..), ExplainSummary(..)
    , SummaryBytes(..), Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Format (padHex, renderField)
import Slap.Measure (Length(..), FileSize(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

xdelta1Meta :: XDelta1Patch -> [(String, String)]
xdelta1Meta patch =
  [ ("version", xdelta1Version patch) ]
  ++ [ ("from", ByteString8.unpack (xdelta1FromName patch))
     , ("to", ByteString8.unpack (xdelta1ToName patch))
     , ("target size", show (unFileSize (xdelta1TargetLength patch)))
     , ("target MD5", md5Hex (xdelta1ToMD5 patch))
     , ("sources", show (length sources))
     ]
  ++ sourceMD5s
  ++ [ ("data seg", show (ByteString.length (xdelta1DataSegment patch)) ++ " bytes") ]
  where
    sources = xdelta1Sources patch
    md5Hex = concatMap (\byte -> padHex 2 (fromIntegral byte)) . ByteString.unpack
    sourceMD5s
      | [entry] <- sources = [("source MD5", md5Hex (xdelta1SourceMD5 entry))]
      | otherwise       = [("source " ++ show index ++ " MD5", md5Hex (xdelta1SourceMD5 entry))
                            | (index, entry) <- zip [(1::Int)..] sources]

xdelta1Info :: XDelta1Patch -> String
xdelta1Info patch = unlines $ filter (not . null) $
  [ "format:      xdelta1 v" ++ xdelta1Version patch ]
  ++ map renderField (xdelta1Meta patch)
  ++ [ sourceLines
     , "instructions:" ++ show (length (xdelta1Instructions patch))
     ]
  where
    sourceLines = unlines
      [ "  [" ++ show index ++ "] " ++ ByteString8.unpack (xdelta1SourceName entry)
        ++ (if xdelta1SourceIsData entry then " (data)" else " (file)")
        ++ (if xdelta1SourceSequential entry then " seq" else "")
        ++ "  " ++ show (unFileSize (xdelta1SourceLength entry)) ++ " bytes"
        ++ "  MD5:" ++ md5Hex (xdelta1SourceMD5 entry)
      | (index, entry) <- zip [(0::Int)..] (xdelta1Sources patch) ]
    md5Hex = concatMap (\byte -> padHex 2 (fromIntegral byte)) . ByteString.unpack

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainXDelta1 :: XDelta1Patch -> ExplainData
explainXDelta1 patch = ExplainData
  { explainFormat   = "xdelta1 v" ++ xdelta1Version patch
  , explainHeader   = xdelta1Meta patch
  , explainSections = map makeXDelta1SourceText (zip [0..] (xdelta1Sources patch))
      ++ [SectionText "", SectionText ("instructions: " ++ show instructionCount), SectionText ""]
      ++ [SectionRegions (map makeXDelta1Region (xdelta1Instructions patch))]
  , explainSummary  = Summary instructionCount "instructions" (Just (fromIntegral (unFileSize (xdelta1TargetLength patch)), BytesTotalOutput))
  , explainNotes    = []
  }
  where
    instructionCount = length (xdelta1Instructions patch)

makeXDelta1SourceText :: (Int, XDelta1Source) -> ExplainSection
makeXDelta1SourceText (index, sourceEntry) = SectionText $
  "  [" ++ show index ++ "] " ++ ByteString8.unpack (xdelta1SourceName sourceEntry)
  ++ (if xdelta1SourceIsData sourceEntry then " (data)" else " (file)")
  ++ (if xdelta1SourceSequential sourceEntry then " seq" else "")
  ++ "  " ++ show (unFileSize (xdelta1SourceLength sourceEntry)) ++ " bytes"
  ++ "  MD5:" ++ concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack (xdelta1SourceMD5 sourceEntry))

makeXDelta1Region :: XDelta1Instruction -> ExplainRegion
makeXDelta1Region instruction = ExplainRegion
  { regionOffset     = xdelta1InstructionOffset instruction
  , regionSize       = Length (fromIntegral (unFileSize (xdelta1InstructionLength instruction)))
  , regionLabel      = "Copy  "
  , regionPayload    = PayloadCopy FromSource
  , regionAnnotation = AnnotAt AtOffset (xdelta1InstructionOffset instruction)
      [DetailSourceIndex (xdelta1InstructionIndex instruction)]
  }
