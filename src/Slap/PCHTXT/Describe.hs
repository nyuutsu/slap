module Slap.PCHTXT.Describe
  ( pchtxtInfo
  , pchtxtMeta
  , explainPCHTXT
  , makePCHTXTBlock
  , makePCHTXTEntry
  ) where

import Slap.PCHTXT.Types (PCHTXTPatch(..), PCHTXTBlock(..), PCHTXTEntry(..))
import Slap.PCHTXT.Create (hexPad)
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                     ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                     SummaryByteInfo(..), SummaryBytes(..), Annotation(..))
import Slap.Format (MetaField(..), renderField)
import Slap.Measure (Offset(..), Length(..), advance, byteLength)

import qualified Data.ByteString as ByteString

pchtxtMeta :: PCHTXTPatch -> [MetaField]
pchtxtMeta patch = case pchtxtNsobid patch of
  Just nsobid -> [MetaField "nsobid" nsobid]
  Nothing     -> []

pchtxtInfo :: PCHTXTPatch -> String
pchtxtInfo patch = unlines $ filter (not . null) $
  [ "format:      PCHTXT (Nintendo Switch)" ]
  ++ map renderField (pchtxtMeta patch)
  ++ [ "blocks:      " ++ show totalBlocks
       ++ " (" ++ show enabledBlockCount ++ " enabled, "
       ++ show disabledBlockCount ++ " disabled)"
     , "entries:     " ++ show totalEntries
     , "total bytes: " ++ show totalBytes
     , rangeString
     ]
  where
    totalBlocks = length (pchtxtBlocks patch)
    enabledBlockCount = length (filter pchtxtBlockEnabled (pchtxtBlocks patch))
    disabledBlockCount = totalBlocks - enabledBlockCount
    enabledEntries = concatMap pchtxtBlockEntries
                       (filter pchtxtBlockEnabled (pchtxtBlocks patch))
    totalEntries = length enabledEntries
    totalBytes = sum (map (ByteString.length . pchtxtData) enabledEntries)
    rangeString
      | null enabledEntries = "range:       (empty patch)"
      | otherwise =
          let lowestOffset = minimum (map (unOffset . pchtxtOffset) enabledEntries)
              highestEnd = unOffset (maximum (map (\entry -> advance (pchtxtOffset entry) (byteLength (pchtxtData entry))) enabledEntries))
          in "range:       0x" ++ hexPad 8 lowestOffset ++ " - 0x" ++ hexPad 8 highestEnd

explainPCHTXT :: PCHTXTPatch -> ExplainData
explainPCHTXT patch = ExplainData
  { explainFormat   = "PCHTXT (Nintendo Switch)"
  , explainHeader   = pchtxtMeta patch
  , explainSections = map makePCHTXTBlock (zip [1..] (pchtxtBlocks patch))
  , explainSummary  = Summary (SummaryInfo (length enabledEntries) "enabled entries" (Just (SummaryByteInfo totalBytes BytesTotal)))
  , explainNotes    = []
  }
  where
    enabledEntries = concatMap pchtxtBlockEntries
                       (filter pchtxtBlockEnabled (pchtxtBlocks patch))
    totalBytes = sum (map (ByteString.length . pchtxtData) enabledEntries)

makePCHTXTBlock :: (Int, PCHTXTBlock) -> ExplainSection
makePCHTXTBlock (index, block) =
  SectionBlock label (map makePCHTXTEntry (pchtxtBlockEntries block))
  where
    status = if pchtxtBlockEnabled block then "enabled" else "disabled"
    description = maybe "" (" -- " ++) (pchtxtBlockDescription block)
    label = "block " ++ show index ++ " (" ++ status ++ ")" ++ description

makePCHTXTEntry :: PCHTXTEntry -> ExplainRegion
makePCHTXTEntry entry = ExplainRegion
  { regionOffset     = pchtxtOffset entry
  , regionSize       = Length (ByteString.length (pchtxtData entry))
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (pchtxtData entry)
  , regionAnnotation = AnnotNone
  }
