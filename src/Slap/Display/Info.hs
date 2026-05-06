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

import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit, ByteCount,
                             FormatHeader, renderFormatHeader,
                             renderCountUnit, pluralCountUnit,
                             renderByteCount, renderOffsetRange)
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
--   rendered to display strings,
-- * a 'Tally' of items in the patch with optional 'ByteCount',
-- * an optional 'OffsetRange' surfacing where the patch operates,
--   populated only when computing it is cheap (formats whose records
--   carry sortable absolute offsets).
data PatchInfo = PatchInfo
  { infoFormat :: !FormatHeader
  , infoLines  :: ![InfoLine]
  , infoTally  :: !Tally
  , infoUnit   :: !CountUnit
  , infoBytes  :: !(Maybe ByteCount)
  , infoRange  :: !(Maybe OffsetRange)
  } deriving (Eq, Show)

-- | Render a 'PatchInfo' as a list of 'InfoLine' rows. The caller
-- ('doInfo') maps 'renderInfoLine' over the result.
renderPatchInfo :: PatchInfo -> [InfoLine]
renderPatchInfo info =
  [ InfoLine "format" (renderFormatHeader (infoFormat info)) ]
  ++ infoLines info
  ++ [ countLine ]
  ++ rangeLineList
  where
    tally       = infoTally info
    countUnit   = infoUnit  info
    countPhrase = show (unTally tally) ++ " " ++ renderCountUnit tally countUnit
    countValue = case infoBytes info of
      Nothing    -> countPhrase
      Just bytes -> countPhrase ++ ", " ++ renderByteCount bytes
    countLine = InfoLine (pluralCountUnit countUnit) countValue
    rangeLineList = case infoRange info of
      Nothing    -> []
      Just range -> [InfoLine "range" (renderOffsetRange range)]

-- | Render a one-line action announcement: @"\<verb\> \<count and
-- bytes\> → \<path\>"@. Used by 'doApply' for both the success path
-- (@"applied"@) and dry-run (@"would apply"@).
renderActionLine :: String -> PatchInfo -> FilePath -> String
renderActionLine actionVerb info outputPath =
  let tally       = infoTally info
      countUnit   = infoUnit  info
      countPhrase = show (unTally tally) ++ " " ++ renderCountUnit tally countUnit
      bytesSuffix = case infoBytes info of
        Nothing    -> ""
        Just bytes -> ", " ++ renderByteCount bytes
  in actionVerb ++ " " ++ countPhrase ++ bytesSuffix
     ++ spacePaddedRightwardsArrow ++ outputPath
