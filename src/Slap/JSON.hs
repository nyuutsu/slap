-- | JSON extraction for slap. Currently used only by EBP metadata
-- handling but lives outside 'Slap.IPS.*' because JSON is not an
-- IPS concern.
--
-- Scope is intentionally narrow. This module assumes UTF-8 input
-- and exposes case-insensitive lookup of string-valued fields at
-- the top level of a JSON object. It does not handle:
--
--   * Non-UTF-8 Unicode encodings (UTF-16, UTF-32). RFC 4627
--     permits these for JSON; RFC 8259 narrowed interchange JSON
--     to UTF-8. Real-world EBP patches are always UTF-8 in
--     practice — the reference patcher (Lyrositor/EBPatcher) uses
--     Python's @json.dumps@ which produces UTF-8 by default.
--
--   * Nested objects, arrays, numeric values, booleans, or nulls.
--     The reference EBPatcher implementation uses Python's full
--     @json.loads@ on read and would parse arbitrarily-nested
--     blobs, so this module is technically narrower than the
--     format permits. In practice, EBP metadata is always a flat
--     object with four string-valued fields ('patcher', 'title',
--     'author', 'description').
--
-- Full spec compliance would require both arbitrary-depth JSON
-- parsing and any-Unicode detection-and-transcode, and would land
-- infrastructure for a use case that effectively does not exist.
-- If a real-world EBP patch ever turns up that exercises these
-- spec corners, this module is the place to harden.
module Slap.JSON
  ( jsonPairs
  , jsonFieldCI
  ) where

import Data.ByteString (ByteString)
import Data.Char (toLower)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text

-- | Extract all string key-value pairs from a flat JSON object.
jsonPairs :: ByteString -> [(String, String)]
jsonPairs = extractPairs . Text.unpack . Text.decodeUtf8Lenient
  where
    extractPairs text = case dropWhile (/= '{') text of
      ('{':rest) -> scanEntries rest
      _          -> []
    scanEntries text = case dropWhile (\char -> char == ' ' || char == ',' || char == '\n' || char == '\r') text of
      ('}':_)    -> []
      ('"':rest) -> case takeQuoted rest of
        (key, afterKey) -> case dropWhile (\char -> char == ' ' || char == ':') afterKey of
          ('"':valueRest) -> case takeQuoted valueRest of
            (value, afterValue) -> (key, value) : scanEntries afterValue
          other -> scanEntries other   -- non-string value, skip
      _ -> []
    takeQuoted = scanQuoted []
      where
        scanQuoted accumulated ('"' : rest)         = (reverse accumulated, rest)
        scanQuoted accumulated ('\\' : '"' : rest)  = scanQuoted ('"' : accumulated) rest
        scanQuoted accumulated ('\\' : '\\' : rest) = scanQuoted ('\\' : accumulated) rest
        scanQuoted accumulated ('\\' : char : rest) = scanQuoted (char : accumulated) rest
        scanQuoted accumulated (char : rest)        = scanQuoted (char : accumulated) rest
        scanQuoted accumulated []                   = (reverse accumulated, [])

-- | Case-insensitive key lookup in extracted JSON pairs.
jsonFieldCI :: [(String, String)] -> String -> Maybe String
jsonFieldCI pairs key =
  let lowerKey = map toLower key
  in lookup lowerKey [(map toLower entryKey, value) | (entryKey, value) <- pairs]
