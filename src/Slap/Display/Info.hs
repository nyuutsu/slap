{-# LANGUAGE OverloadedStrings #-}

-- | The cheap-path display carrier: 'PatchInfo'.
-- Populated by every 'parseSomePatchFrom\<Format\>' helper in 'Slap.SomePatch' at parse time, without any per-record analytical work.
-- Consumed by 'doInfo' (via 'patchInfo') for @slap info@, and by 'doApply' and 'doUndo' for their action announcement lines.
module Slap.Display.Info
  ( -- * The cheap-path carrier
    PatchInfo(..)
  , renderPatchInfo
    -- * Action-line rendering
  , renderActionLine
    -- * The verification report
  , InputSideVerdict(..)
  , OutputSideVerdict(..)
  , renderVerificationReport
  ) where

import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (catMaybes)
import Data.Text (Text)
import qualified Data.Text as Text
import Slap.Display.Common (InfoLine(..), renderInfoLine, Tally(..), CountUnit, ByteCount,
                             FormatHeader, renderFormatHeader,
                             renderCountUnit, pluralCountUnit,
                             renderByteCount, renderOffsetRange,
                             renderAsText, proseList)
import Slap.Display.EmbeddedContent (EmbeddedContent, EmbeddedDepth(..), renderEmbedded)
import Slap.Display.Glyph (spacePaddedRightwardsArrow)
import Slap.Measure (OffsetRange)
import Slap.Status (declaredCheckKindNoun)
import Slap.Verify (VerificationVerdict(..), DeclaredCheckKind)

-- | What @slap info@ shows about a patch.
-- Populated cheaply at parse time: every field is a fact the format helper already had at hand,
-- with the optional 'infoRange' and total-payload-byte count being single linear passes over the records.
--
-- 'infoRange' stays 'Nothing' for formats whose records don't carry sortable absolute offsets:
-- for those, computing it would not be cheap.
data PatchInfo = PatchInfo
  { infoFormat   :: !FormatHeader
  , infoLines    :: ![InfoLine]
  , infoEmbedded :: ![EmbeddedContent]
  , infoTally    :: !Tally
  , infoUnit     :: !CountUnit
  , infoBytes    :: !(Maybe ByteCount)
  , infoRange    :: !(Maybe OffsetRange)
  } deriving (Eq, Show)

-- | 'SizeOnly' is the @slap info@ glance;
-- 'WithPayload' opens each embedded field's content beneath its size line — the extra @slap explain@ shows.
renderPatchInfo :: EmbeddedDepth -> PatchInfo -> [Text]
renderPatchInfo depth info =
  renderInfoLine (InfoLine "format" (renderFormatHeader (infoFormat info)))
  : map renderInfoLine (infoLines info)
  ++ concatMap (renderEmbedded depth) (infoEmbedded info)
  ++ [ renderInfoLine countLine ]
  ++ rangeLines
  where
    tally       = infoTally info
    countUnit   = infoUnit  info
    countPhrase = renderAsText (unTally tally) <> " " <> renderCountUnit tally countUnit
    countValue = case infoBytes info of
      Nothing    -> countPhrase
      Just bytes -> countPhrase <> ", " <> renderByteCount bytes
    countLine = InfoLine (pluralCountUnit countUnit) countValue
    rangeLines = case infoRange info of
      Nothing    -> []
      Just range -> [ renderInfoLine (InfoLine "range" (renderOffsetRange range)) ]

-- | Render a one-line action announcement: @"\<verb\> \<count and bytes\> → \<path\>"@.
-- Used by 'doApply' (@"applied"@) and 'doUndo' (@"reverted"@).
renderActionLine :: Text -> PatchInfo -> FilePath -> Text
renderActionLine actionVerb info outputPath =
  let tally       = infoTally info
      countUnit   = infoUnit  info
      countPhrase = renderAsText (unTally tally) <> " " <> renderCountUnit tally countUnit
      bytesSuffix = case infoBytes info of
        Nothing    -> ""
        Just bytes -> ", " <> renderByteCount bytes
  in actionVerb <> " " <> countPhrase <> bytesSuffix
     <> spacePaddedRightwardsArrow <> Text.pack outputPath

-- | The verdict on the file the user handed in.
newtype InputSideVerdict = InputSideVerdict VerificationVerdict
  deriving (Eq, Show)

-- | The verdict on the file slap produced; 'InputSideVerdict''s counterpart.
newtype OutputSideVerdict = OutputSideVerdict VerificationVerdict
  deriving (Eq, Show)

-- | The happy-path answer to "did the files agree with the patch?" — one line per side,
-- collapsed to one line when the patch declares nothing at all, each match naming the kinds of check it rests on.
-- A differing side contributes no line: its mismatch warnings have already said more.
renderVerificationReport :: InputSideVerdict -> OutputSideVerdict -> [Text]
renderVerificationReport (InputSideVerdict inputVerdict) (OutputSideVerdict outputVerdict) =
  case (inputVerdict, outputVerdict) of
    (VerdictUncheckable, VerdictUncheckable) -> ["the patch carries no checks, so nothing was compared"]
    _ -> catMaybes [sideLine "input" inputVerdict, sideLine "output" outputVerdict]
  where
    sideLine sideLabel (VerdictMatches heldKinds) = Just (sideLabel <> " matches the patch's " <> heldKindsPhrase heldKinds)
    sideLine sideLabel VerdictUncheckable         = Just ("the patch carries no checks for the " <> sideLabel)
    sideLine _         (VerdictDiffers _)         = Nothing

heldKindsPhrase :: NonEmpty DeclaredCheckKind -> Text
heldKindsPhrase = proseList . map declaredCheckKindNoun . NonEmpty.toList
