{-# LANGUAGE OverloadedStrings #-}

-- | Shared display-layer vocabulary used by both 'Slap.Display.Info'
-- (cheap-path) and 'Slap.Display.Analysis' (analytical-path). The
-- types and renderers here have no commitment to one or the other —
-- 'InfoLine' is a label-value display row regardless of which carrier
-- produced it; 'Tally', 'CountUnit', 'ByteCount' express counts and
-- byte-totals identically across both paths.
module Slap.Display.Common
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
    -- * Format headers
  , FormatHeader(..)
  , renderFormatHeader
    -- * Range rendering
  , renderOffsetRange
    -- * Show-to-Text
  , renderAsText
  , renderHexAsText
    -- * FilePath ↔ Text boundary
  , pathText
  ) where

import Data.Text (Text)
import qualified Data.Text as Text
import Numeric (showHex)
import Slap.Display.Primitives (padHex)
import Slap.FormatLabel (FormatLabel, formatLabelName)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     OffsetRange(..), rangeLastByte)

----------------------------------------------------------------------------
-- InfoLine
----------------------------------------------------------------------------

-- | A label-value display row. Rendered by 'renderInfoLine' with
-- column-13 alignment ("source size:  1024"). Both fields are 'Text'
-- by convention — the label set across formats is open and proliferates,
-- so a closed sum or newtype wouldn't pay for the constructor surface
-- or wrapping ceremony, and the value has been
-- rendered to display form by the time it lands here. Labels are
-- lowercase with no trailing colon — 'renderInfoLine' adds the colon
-- and the alignment padding.
data InfoLine = InfoLine
  { infoLineLabel :: !Text
  , infoLineValue :: !Text
  } deriving (Eq, Show)

-- | Render an 'InfoLine' with column-13 alignment.
renderInfoLine :: InfoLine -> Text
renderInfoLine (InfoLine label value) =
  label <> ":" <> Text.replicate (max 1 (13 - Text.length label - 1)) " " <> value

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
  | EnabledEntries
  deriving (Eq, Show)

-- | Render a 'CountUnit' inflected by count: 1 returns the singular
-- form, anything else returns the plural. Used as the suffix in the
-- count line ("23 records" vs. "1 record").
renderCountUnit :: Tally -> CountUnit -> Text
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
renderCountUnit (Tally 1) Entries        = "entry"
renderCountUnit _         Entries        = "entries"
renderCountUnit (Tally 1) EnabledEntries = "enabled entry"
renderCountUnit _         EnabledEntries = "enabled entries"

-- | The plural form of a 'CountUnit', independent of count. Used
-- when the unit name appears as a label rather than a count suffix
-- ("records:  23" — the label is plural even when the count happens
-- to be 1, matching slap's display convention).
pluralCountUnit :: CountUnit -> Text
pluralCountUnit Records       = "records"
pluralCountUnit Actions       = "actions"
pluralCountUnit Blocks        = "blocks"
pluralCountUnit Windows       = "windows"
pluralCountUnit Commands      = "commands"
pluralCountUnit Instructions  = "instructions"
pluralCountUnit Entries        = "entries"
pluralCountUnit EnabledEntries = "enabled entries"

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

renderByteCount :: ByteCount -> Text
renderByteCount (TotalOutputBytes (FileSize n)) =
  renderAsText n <> " bytes total output"
renderByteCount (TotalPayloadBytes (Length n)) =
  renderAsText n <> " bytes total"

----------------------------------------------------------------------------
-- OffsetRange rendering
----------------------------------------------------------------------------

-- | Render an 'OffsetRange' for display: @0xLOW - 0xHIGH@ using the
-- inclusive last byte ('rangeLastByte'). The hex literal is six
-- digits wide, matching the convention used by
-- 'Slap.Display.Analysis''s summary range line.
renderOffsetRange :: OffsetRange -> Text
renderOffsetRange range =
  "0x" <> padHex 6 (unOffset (rangeStart range))
  <> " - 0x"
  <> padHex 6 (unOffset (rangeLastByte range))

----------------------------------------------------------------------------
-- FormatHeader
----------------------------------------------------------------------------

-- | The format-name part of a display header. The 'FormatLabel' is
-- the canonical typed identity ('LabelBPS', 'LabelPPF3', etc.); the
-- 'formatExtra' is an optional free-form suffix that depends on
-- parsed-value facts the label doesn't carry — VCDIFF's xdelta3
-- variant, NINJA1's sub-format string, xdelta1's version, the
-- @"\/Yay0"@ suffix added when the patch arrived inside a Yay0
-- envelope. The renderer composes them by simple text concatenation,
-- so 'formatExtra' includes its own leading separator (e.g.
-- @Just \" (xdelta3)\"@, @Just \"\/Yay0\"@).
data FormatHeader = FormatHeader
  { formatLabel :: !FormatLabel
  , formatExtra :: !(Maybe Text)
  } deriving (Eq, Show)

renderFormatHeader :: FormatHeader -> Text
renderFormatHeader (FormatHeader label extra) =
  formatLabelName label <> maybe "" id extra

----------------------------------------------------------------------------
-- Show-to-Text
----------------------------------------------------------------------------

-- | The @'show' :: Show a => a -> 'String'@ to 'Text' bridge. Used
-- wherever an 'Int' or other 'Show' value is interpolated into
-- display text; inlining @'Text.pack' . 'show'@ everywhere would
-- be noise.
renderAsText :: Show a => a -> Text
renderAsText = Text.pack . show

-- | Render an unsigned hex value as 'Text' without prefix or padding —
-- the unpadded peer of 'Slap.Display.Primitives.padHex'. Use when a
-- @0x@ literal needs the natural width of the underlying value rather
-- than a fixed column. Wraps 'Numeric.showHex' so call sites stop
-- restating the @Text.pack (showHex value "")@ shape.
renderHexAsText :: Integral a => a -> Text
renderHexAsText value = Text.pack (showHex value "")

----------------------------------------------------------------------------
-- FilePath ↔ Text boundary
----------------------------------------------------------------------------

-- | Lift a 'FilePath' (slap honours it as 'String') into 'Text' for
-- interpolation into a 'Text' diagnostic. The lift is named so the
-- 'FilePath' → 'Text' boundary is visible at every site it crosses,
-- rather than hidden behind an 'OverloadedStrings'-style implicit
-- conversion.
pathText :: FilePath -> Text
pathText = Text.pack
