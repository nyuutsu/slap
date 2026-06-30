{-# LANGUAGE OverloadedStrings #-}

module Slap.Display.Glyph
  ( -- * Display glyphs
    rightwardsArrow
  , checkMark
  , ballotX
  , emDash
  , spacePaddedRightwardsArrow
  , spacePaddedEnDash
  ) where

import Data.Text (Text)
import qualified Data.Text as Text

-- The codepoints below are domain symbols in slap's CLI output
-- (output redirection, verification status, range separators,
-- sentence-internal pause).  Naming them once means call sites
-- read as the meaning they carry rather than as a numeric escape.

-- | U+2192 (→).  Output redirection in CLI status lines, e.g.
-- @applied 23 records → output.bin@.
rightwardsArrow :: Char
rightwardsArrow = '\8594'

-- | U+2713 (✓).  Verification success in dry-run output.
checkMark :: Char
checkMark = '\10003'

-- | U+2717 (✗).  Verification failure in dry-run output, paired
-- with the expected value.
ballotX :: Char
ballotX = '\10007'

-- | U+2013 (–).  Inclusive range separator in Explain output, e.g.
-- @0x000000 – 0x00FFFF@.
enDash :: Char
enDash = '\8211'

-- | U+2014 (—).  Sentence-internal pause in error messages.
emDash :: Char
emDash = '\8212'

-- | Joins the two sides of a CLI status line, as in @INPUT → OUTPUT@.
spacePaddedRightwardsArrow :: Text
spacePaddedRightwardsArrow = Text.pack [' ', rightwardsArrow, ' ']

-- | Spans an Explain byte range, as in @0x000000 – 0x00FFFF@.
spacePaddedEnDash :: Text
spacePaddedEnDash = Text.pack [' ', enDash, ' ']
