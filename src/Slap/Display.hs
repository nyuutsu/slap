-- | Display-layer types for the cheap path: @slap info@ and @slap apply@.
--
-- These are structured carriers populated at parse time without any
-- per-record analytical work — no section-building, no per-record
-- annotation, no payload classification. The expensive analytical
-- carrier is 'Slap.Explain.ExplainData', built only when @slap explain@
-- needs it.
--
-- The cheap path's contract: every field on 'PatchHeader' is a fact
-- the format helper already knew at parse time and trivially carries
-- across without a fold over the record stream — except for the
-- optional 'headerRange' and the optional total-payload byte count,
-- which are single linear passes over the records and are still
-- cheap relative to the per-record annotation work the explain
-- carrier performs.
module Slap.Display
  ( -- * Display rows
    InfoLine(..)
  , renderInfoLine
    -- * Counts
  , Tally(..)
  , CountUnit(..)
  , renderCountUnit
  , pluralCountUnit
  , ByteCount(..)
  , renderByteCount
    -- * Headers
  , FormatHeader(..)
  , renderFormatHeader
  , PatchHeader(..)
  , renderPatchHeader
    -- * Ranges
  , renderOffsetRange
    -- * Re-exports
  , OffsetRange(..)
  ) where

import Slap.Format (padHex)
import Slap.FormatLabel (FormatLabel, formatLabelName)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     OffsetRange(..), rangeLastByte)

----------------------------------------------------------------------------
-- InfoLine
----------------------------------------------------------------------------

-- | A label-value display row. Rendered by 'renderInfoLine' with
-- column-13 alignment ("source size:  1024"). Both fields are bare
-- 'String' by convention — the label set across formats is open and
-- proliferates (~30 distinct labels), so a closed sum or newtype
-- wouldn't pay for the constructor surface or wrapping ceremony, and
-- the value has been rendered to display form by the time it lands
-- here. Labels are lowercase with no trailing colon — 'renderInfoLine'
-- adds the colon and the alignment padding.
data InfoLine = InfoLine
  { infoLineLabel :: !String
  , infoLineValue :: !String
  } deriving (Eq, Show)

-- | Render an 'InfoLine' with column-13 alignment.
renderInfoLine :: InfoLine -> String
renderInfoLine (InfoLine label value) =
  label ++ ":" ++ replicate (max 1 (13 - length label - 1)) ' ' ++ value

----------------------------------------------------------------------------
-- Tally and CountUnit
----------------------------------------------------------------------------

-- | A non-negative count of items in a patch. Newtype-wrapped so it
-- can't be confused with offsets, sizes, or any other 'Int'-shaped
-- role. Travels paired with a 'CountUnit' that names what is being
-- counted.
newtype Tally = Tally { unTally :: Int }
  deriving (Eq, Show)

-- | The closed set of unit labels used in display-layer counts. Each
-- format's helper picks the unit that matches what the format counts
-- ('Records' for IPS, 'Actions' for BPS, 'Windows' for VCDIFF, etc.).
-- New formats add a constructor here and 'renderCountUnit' /
-- 'pluralCountUnit' grow exhaustive arms; @-Wincomplete-patterns@
-- fires if a constructor is forgotten.
data CountUnit
  = Records
  | Actions
  | Blocks
  | Windows
  | Commands
  | Instructions
  | Entries
  | ControlTuples
  deriving (Eq, Show)

-- | Render a 'CountUnit' inflected by count: 1 returns the singular
-- form, anything else returns the plural. Used as the suffix in the
-- count line ("23 records" vs. "1 record").
renderCountUnit :: Tally -> CountUnit -> String
renderCountUnit (Tally 1) Records       = "record"
renderCountUnit _         Records       = "records"
renderCountUnit (Tally 1) Actions       = "action"
renderCountUnit _         Actions       = "actions"
renderCountUnit (Tally 1) Blocks        = "block"
renderCountUnit _         Blocks        = "blocks"
renderCountUnit (Tally 1) Windows       = "window"
renderCountUnit _         Windows       = "windows"
renderCountUnit (Tally 1) Commands      = "command"
renderCountUnit _         Commands      = "commands"
renderCountUnit (Tally 1) Instructions  = "instruction"
renderCountUnit _         Instructions  = "instructions"
renderCountUnit (Tally 1) Entries       = "entry"
renderCountUnit _         Entries       = "entries"
renderCountUnit (Tally 1) ControlTuples = "control tuple"
renderCountUnit _         ControlTuples = "control tuples"

-- | The plural form of a 'CountUnit', independent of count. Used
-- when the unit name appears as a label rather than a count suffix
-- ("records:  23" — the label is plural even when the count happens
-- to be 1, matching slap's display convention).
pluralCountUnit :: CountUnit -> String
pluralCountUnit Records       = "records"
pluralCountUnit Actions       = "actions"
pluralCountUnit Blocks        = "blocks"
pluralCountUnit Windows       = "windows"
pluralCountUnit Commands      = "commands"
pluralCountUnit Instructions  = "instructions"
pluralCountUnit Entries       = "entries"
pluralCountUnit ControlTuples = "control tuples"

----------------------------------------------------------------------------
-- ByteCount
----------------------------------------------------------------------------

-- | A byte count attached to a 'Tally', distinguishing two semantic
-- kinds:
--
-- * 'TotalOutputBytes' is the declared size of the produced file —
--   used by formats that record their target's file size in the
--   patch header (BPS, UPS, VCDIFF, xdelta1).
--
-- * 'TotalPayloadBytes' is the sum of payload bytes across all
--   records — used by formats whose records each carry a chunk of
--   replacement bytes; the sum tells the user how much data the
--   patch is /carrying/, not how big the output will be.
--
-- The two are different facts even when their numerical values
-- happen to coincide, and 'renderByteCount' distinguishes them with
-- different display text.
data ByteCount
  = TotalOutputBytes  !FileSize
  | TotalPayloadBytes !Length
  deriving (Eq, Show)

renderByteCount :: ByteCount -> String
renderByteCount (TotalOutputBytes (FileSize n)) =
  show n ++ " bytes total output"
renderByteCount (TotalPayloadBytes (Length n)) =
  show n ++ " bytes total"

----------------------------------------------------------------------------
-- OffsetRange rendering
----------------------------------------------------------------------------

-- | Render an 'OffsetRange' for display: @0xLOW - 0xHIGH@ using the
-- inclusive last byte ('rangeLastByte'). The hex literal is six
-- digits wide, matching the convention used by 'Slap.Explain''s
-- summary range line.
renderOffsetRange :: OffsetRange -> String
renderOffsetRange range =
  "0x" ++ padHex 6 (unOffset (rangeStart range))
  ++ " - 0x"
  ++ padHex 6 (unOffset (rangeLastByte range))

----------------------------------------------------------------------------
-- FormatHeader and PatchHeader
----------------------------------------------------------------------------

-- | The format-name part of a display header. The 'FormatLabel' is
-- the canonical typed identity ('LabelBPS', 'LabelPPF3', etc.); the
-- 'formatExtra' is an optional free-form suffix that depends on
-- parsed-value facts the label doesn't carry — VCDIFF's xdelta3
-- variant, NINJA1's sub-format string, xdelta1's version, the
-- @"\/Yay0"@ suffix added when the patch arrived inside a Yay0
-- envelope. The renderer composes them by simple string concatenation,
-- so 'formatExtra' includes its own leading separator (e.g.
-- @Just \" (xdelta3)\"@, @Just \"\/Yay0\"@).
data FormatHeader = FormatHeader
  { formatLabel :: !FormatLabel
  , formatExtra :: !(Maybe String)
  } deriving (Eq, Show)

renderFormatHeader :: FormatHeader -> String
renderFormatHeader (FormatHeader label extra) =
  formatLabelName label ++ maybe "" id extra

-- | The cheap display carrier consumed by 'doInfo' and 'doApply'.
-- Composed of:
--
-- * the format-name with optional elaboration ('headerFormat'),
-- * the format-specific metadata fields ('headerLines') already
--   rendered to display strings,
-- * a 'Tally' of items in the patch with optional 'ByteCount',
-- * an optional 'OffsetRange' surfacing where the patch operates,
--   populated only when computing it is cheap (formats whose records
--   carry sortable absolute offsets).
data PatchHeader = PatchHeader
  { headerFormat :: !FormatHeader
  , headerLines  :: ![InfoLine]
  , headerTally  :: !Tally
  , headerUnit   :: !CountUnit
  , headerBytes  :: !(Maybe ByteCount)
  , headerRange  :: !(Maybe OffsetRange)
  } deriving (Eq, Show)

-- | Render a 'PatchHeader' as a list of 'InfoLine' rows. The caller
-- ('doInfo') maps 'renderInfoLine' over the result.
renderPatchHeader :: PatchHeader -> [InfoLine]
renderPatchHeader header =
  [ InfoLine "format" (renderFormatHeader (headerFormat header)) ]
  ++ headerLines header
  ++ [ countLine ]
  ++ rangeLineList
  where
    tally       = headerTally header
    countUnit   = headerUnit  header
    countPhrase = show (unTally tally) ++ " " ++ renderCountUnit tally countUnit
    countValue = case headerBytes header of
      Nothing    -> countPhrase
      Just bytes -> countPhrase ++ ", " ++ renderByteCount bytes
    countLine = InfoLine (pluralCountUnit countUnit) countValue
    rangeLineList = case headerRange header of
      Nothing    -> []
      Just range -> [InfoLine "range" (renderOffsetRange range)]
