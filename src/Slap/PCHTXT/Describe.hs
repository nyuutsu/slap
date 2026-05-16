module Slap.PCHTXT.Describe
  ( pchtxtMeta
  , analyzePCHTXT
  , makePCHTXTBlock
  , makePCHTXTEntry
  , pchtxtEntriesRange
  ) where

import Slap.PCHTXT.Types (PCHTXTPatch(..), PCHTXTBlock(..), PCHTXTEntry(..))
import Slap.Display.Analysis (PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..),
                     AnalysisPayload(..), AnalysisSummary(..), SummaryInfo(..),
                     Annotation(..))
import Slap.Display.Common (InfoLine(..),
                     Tally(..), CountUnit(..), ByteCount(..))
import Slap.Measure (Offset(..), Length(..),
                     OffsetRange(..), advance, byteLength)

import qualified Data.ByteString as ByteString

pchtxtMeta :: PCHTXTPatch -> [InfoLine]
pchtxtMeta patch =
  nsobidLine
  ++ [InfoLine "blocks" blocksValue]
  where
    nsobidLine = case pchtxtNsobid patch of
      Just nsobid -> [InfoLine "nsobid" nsobid]
      Nothing     -> []
    blocksValue = show totalBlocks
      ++ " (" ++ show enabledBlockCount ++ " enabled, "
      ++ show disabledBlockCount ++ " disabled)"
    totalBlocks = length (pchtxtBlocks patch)
    enabledBlockCount = length (filter pchtxtBlockEnabled (pchtxtBlocks patch))
    disabledBlockCount = totalBlocks - enabledBlockCount

analyzePCHTXT :: PCHTXTPatch -> PatchAnalysis
analyzePCHTXT patch = PatchAnalysis
  { analysisSections = map makePCHTXTBlock (zip [1..] (pchtxtBlocks patch))
  , analysisSummary  = Summary (SummaryInfo (Tally (length enabledEntries)) EnabledEntries (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    enabledEntries = concatMap pchtxtBlockEntries
                       (filter pchtxtBlockEnabled (pchtxtBlocks patch))
    totalBytes = sum (map (ByteString.length . pchtxtData) enabledEntries)

makePCHTXTBlock :: (Int, PCHTXTBlock) -> AnalysisSection
makePCHTXTBlock (index, block) =
  SectionBlock label (map makePCHTXTEntry (pchtxtBlockEntries block))
  where
    status = if pchtxtBlockEnabled block then "enabled" else "disabled"
    description = maybe "" (" -- " ++) (pchtxtBlockDescription block)
    label = "block " ++ show index ++ " (" ++ status ++ ")" ++ description

makePCHTXTEntry :: PCHTXTEntry -> AnalysisRegion
makePCHTXTEntry entry = AnalysisRegion
  { regionOffset     = pchtxtOffset entry
  , regionSize       = byteLength (pchtxtData entry)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (pchtxtData entry)
  , regionAnnotation = AnnotationNone
  }

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty list of enabled PCHTXT
-- entries, consumed by the cheap display path's
-- 'Slap.Display.Info.PatchInfo' construction. Returns 'Nothing' on an
-- empty list so the display layer suppresses the range line.
pchtxtEntriesRange :: [PCHTXTEntry] -> Maybe OffsetRange
pchtxtEntriesRange [] = Nothing
pchtxtEntriesRange entries =
  let firstAffectedOffset = minimum (map pchtxtOffset entries)
      endOfLastRecord     = maximum (map entryEndOffset entries)
  in Just OffsetRange
      { rangeStart  = firstAffectedOffset
      , rangeLength = Length (unOffset endOfLastRecord - unOffset firstAffectedOffset)
      }
  where
    entryEndOffset entry =
      advance (pchtxtOffset entry) (byteLength (pchtxtData entry))
