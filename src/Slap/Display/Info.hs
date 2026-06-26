{-# LANGUAGE OverloadedStrings #-}

-- | The cheap-path display carrier: 'PatchInfo'. Populated by every
-- 'parseSomePatchFrom\<Format\>' helper in 'Slap.SomePatch' at parse
-- time, without any per-record analytical work. Consumed by 'doInfo'
-- (via 'patchInfo' on a parsed 'SomePatch') for @slap info@, and by
-- 'doApply' for the announcement line on apply success and dry-run.
module Slap.Display.Info
  ( -- * The cheap-path carrier
    PatchInfo(..)
  , renderPatchInfo
    -- * Action-line rendering
  , renderActionLine
  ) where

import Data.Text (Text)
import qualified Data.Text as Text
import Slap.Display.Common (InfoLine(..), renderInfoLine, Tally(..), CountUnit, ByteCount,
                             FormatHeader, renderFormatHeader,
                             renderCountUnit, pluralCountUnit,
                             renderByteCount, renderOffsetRange,
                             renderAsText)
import Slap.Display.EmbeddedContent (EmbeddedContent, EmbeddedDepth(..), renderEmbedded)
import Slap.Display.Glyph (spacePaddedRightwardsArrow)
import Slap.Measure (OffsetRange)

-- | What @slap info@ shows about a patch. Populated cheaply at parse
-- time: every field is a fact the format helper already had at hand,
-- with the optional 'infoRange' and total-payload-byte count being
-- single linear passes over the records.
--
-- Composed of:
--
-- * the format-name with optional elaboration ('infoFormat'),
-- * the format-specific metadata fields ('infoLines') already
--   rendered to display text,
-- * the embedded content the patch carries ('infoEmbedded'), each shown
--   here as a size glance and in @explain@ as its full payload,
-- * a 'Tally' of items in the patch with optional 'ByteCount',
-- * an optional 'OffsetRange' surfacing where the patch operates,
--   populated only when computing it is cheap (formats whose records
--   carry sortable absolute offsets).
data PatchInfo = PatchInfo
  { infoFormat   :: !FormatHeader
  , infoLines    :: ![InfoLine]
  , infoEmbedded :: ![EmbeddedContent]
  , infoTally    :: !Tally
  , infoUnit     :: !CountUnit
  , infoBytes    :: !(Maybe ByteCount)
  , infoRange    :: !(Maybe OffsetRange)
  } deriving (Eq, Show)

-- | Render a 'PatchInfo' to its display lines.
-- 'SizeOnly' is the @slap info@ glance;
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

-- | Render a one-line action announcement: @"\<verb\> \<count and
-- bytes\> → \<path\>"@. Used by 'doApply' for both the success path
-- (@"applied"@) and dry-run (@"would apply"@). The path is taken as
-- 'FilePath' (slap's filename type) and lifted into 'Text' here so
-- the action line is uniformly 'Text'.
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
