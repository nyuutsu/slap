-- | Typed text values that carry their own encoding. Where the
-- predecessor scheme threaded the encoding decision implicitly
-- through which function happened to get called (an
-- @encodeLocaleField@ vs an @encodeUtf8Field@), this module
-- represents the encoding decision in the value itself.
--
-- An 'EncodedText' bundles an 'EncodingName' tag with a 'Text' payload.
-- The tag remembers what encoding the bytes were when they arrived (or
-- what encoding slap is asked to interpret them as); the 'Text'
-- payload is the in-memory canonical form, codepoints, encoding-
-- independent. Transcoding becomes principled: convert between
-- encodings by routing the payload through 'encodeText' or
-- 'encodeTextLenient' under a different tag, with the loss semantics
-- of the conversion surfaced via 'LossNotice'.
--
-- == Module surface
--
-- Three pairs of primitives, picked by whether the call site wants a
-- strict refusal on failure ('Either') or a lenient substitution
-- with loss-reporting (tuple of bytes and notices):
--
--   * 'encodeText' / 'decodeText' — strict. Fails on codepoints
--     the target encoding can't represent ('encodeText'), or on
--     bytes that don't match the declared encoding ('decodeText').
--     The errors carry enough position information to construct
--     a 'Slap.Status.SlapError' at the call site.
--
--   * 'encodeTextLenient' / 'decodeTextLenient' — never fail.
--     'encodeTextLenient' substitutes 'U+FFFD' (or @\'?\'@ for
--     ASCII-only targets) for unrepresentable codepoints;
--     'decodeTextLenient' substitutes 'U+FFFD' for byte sequences
--     that don't decode. Substitutions are reported through the
--     'LossNotice' list so the caller decides whether each one
--     surfaces as a 'Slap.Status.SlapAdvisory'.
--
--   * 'encodeTextBounded' — fixed-width-field encode. Codepoint-
--     aware truncation under the target encoding: encodes codepoint
--     by codepoint, stopping when the next would overflow a byte
--     limit. Result is always valid bytes in the target encoding
--     (no split codepoints) and at most the requested byte count;
--     truncation and substitution both surface through the
--     'LossNotice' list.
--
-- Plus 'processLocaleEncoder', the resolved encoder for the
-- @EncodingLocale@ tag (see below).
--
-- == UTF-8 vs everything-else asymmetry
--
-- The UTF-8 path routes through 'Data.Text.Encoding' — the @text@
-- package's native fast UTF-8 codec. Every other encoding routes
-- through the @encoding@ library (@Data.Encoding@). The asymmetry
-- is a capability-and-speed call: @text@ ships a fast UTF-8 codec
-- but only UTF-8, while @encoding@ ships a structured API that
-- 'encodeTextLenient' and 'encodeTextBounded' need (per-character
-- 'encodeable' predicate, exception-aware @Explicit@ variants,
-- alias-table runtime lookup via 'encodingFromString'). Routing
-- UTF-8 through @encoding@ to unify the paths would be slower
-- without buying anything; routing the non-UTF-8 encodings through
-- @text@ isn't possible.
--
-- == The locale resolver
--
-- 'EncodingLocale' is a catch-all tag meaning "whatever the process
-- locale was at parse or create time." Resolution from the GHC-
-- reported locale name to an @encoding@-library encoder happens once,
-- in the 'processLocaleEncoder' CAF, paired with an optional
-- 'Slap.Status.SlapAdvisory'. On the happy path the advisory is
-- 'Nothing' and the encoder is whatever the locale resolves to; on a
-- name the library doesn't recognize the encoder falls back to UTF-8
-- and the advisory is 'Just' 'Slap.Status.LocaleEncoderUnresolved'.
-- Advisory-as-value lets call sites decide when (and whether) to
-- surface it; the resolver does not 'emitAdvisory' on its own.
--
-- == What the encoding tag remembers
--
-- When 'decodeText' produces an 'EncodedText', the tag is the
-- encoding the caller asked slap to decode as. For
-- 'EncodingLocale' that means "this value was decoded under the
-- process's locale, whatever the locale happens to be." A later
-- 'encodeText' or 'encodeTextLenient' under the same tag will route
-- through the locale resolver again — using whatever the locale is
-- at re-encode time, which may differ from decode time if the
-- process's locale changed in between. The tag preserves the
-- "this is locale, follow the running locale" semantics through
-- the value's lifetime; resolving to a concrete encoder at decode
-- time would lose that and force every later transcode site to
-- guess again.
module Slap.Text
  ( -- * Encoding tag
    EncodingName(..)

    -- * Typed text value
  , EncodedText(..)

    -- * Strict primitives
  , encodeText
  , decodeText
  , EncodeError(..)
  , DecodeError(..)

    -- * Lenient primitives
  , encodeTextLenient
  , decodeTextLenient
  , LossNotice(..)

    -- * Bounded encoding (fixed-width fields)
  , encodeTextBounded

    -- * Locale resolution
  , processLocaleEncoder

    -- * Advisory adaptation
  , decodeLossAdvisories
  , encodeLossAdvisories
  ) where

import Control.Applicative ((<|>))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower, toUpper)
import qualified Data.Encoding as Encoding
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding
import GHC.IO.Encoding (getLocaleEncoding, textEncodingName)
import Slap.FieldName (FieldName)
import Slap.FormatLabel (FormatLabel)
import Slap.Measure (Length(..), OriginalLength(..), TruncatedLength(..),
                     SubstitutionCount(..))
import Slap.Status (SlapAdvisory(..))
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- Tag
----------------------------------------------------------------------------

-- | Which encoding a text value's bytes are in (or are to be
-- interpreted as). Two cases at this stage: 'EncodingUtf8' for
-- the well-defined Unicode case, 'EncodingLocale' for "follow the
-- running process locale". Adding constructors here is the path
-- for future stages that need to honor specific declared encodings
-- on the wire (Shift-JIS, Big5, Latin-1, etc.).
data EncodingName
  = EncodingUtf8
  | EncodingLocale
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- Value
----------------------------------------------------------------------------

-- | A 'Text' value paired with the encoding it was decoded from
-- (or that it is intended to be encoded as). The 'Text' is the
-- in-memory canonical form — Unicode codepoints, encoding-
-- independent. The 'encodedTextEncoding' tag carries provenance
-- forward: a downstream transcode site can see what encoding the
-- value came from and route a re-encode appropriately.
--
-- Constructor public; this is a transport, not a smart-constructed
-- invariant. Producers come from 'decodeText' / 'decodeTextLenient'
-- (one tag-correct path) and from call-site-level wrapping (when
-- the caller already knows the encoding they're declaring on the
-- value, e.g. an EBP @description@ field that is UTF-8 by spec).
data EncodedText = EncodedText
  { encodedTextEncoding :: !EncodingName
  , encodedTextContent  :: !Text
  } deriving (Eq, Show)

----------------------------------------------------------------------------
-- Errors
----------------------------------------------------------------------------

-- | A strict 'encodeText' refusal. Names the target encoding, the
-- first codepoint that wasn't representable in it, and the
-- codepoint's 0-indexed position in the source 'Text'. Call sites
-- lift this into a 'Slap.Status.SlapError'-flavored refusal; the
-- shape here is the raw signal, not the user-facing message.
data EncodeError = EncodeError
  { encodeErrorEncoding  :: !EncodingName
  , encodeErrorCodepoint :: !Char
  , encodeErrorPosition  :: !Int
  } deriving (Eq, Show)

-- | A strict 'decodeText' refusal. Names the encoding slap was
-- trying to decode as, plus the underlying library's diagnostic
-- as a 'String'. Position information is best-effort — the
-- @encoding@ library's exception type does not always carry a
-- precise byte offset, so the 'String' is the most useful signal
-- callers can lift into a 'Slap.Status.SlapError'.
data DecodeError = DecodeError
  { decodeErrorEncoding :: !EncodingName
  , decodeErrorMessage  :: !String
  } deriving (Eq, Show)

----------------------------------------------------------------------------
-- Loss notices (lenient and bounded paths)
----------------------------------------------------------------------------

-- | What got lost when a lenient encode, lenient decode, or a
-- bounded encode finished without a 'Left'. Three cases:
--
--   * 'SubstitutedCodepoint' — encode-side: a single codepoint in
--     the source was not representable in the target encoding and
--     was replaced with the encoding's substitute character (U+FFFD
--     when the target represents it, @\'?\'@ otherwise). The
--     'Char' is the original codepoint; the 'Int' is its 0-indexed
--     position in the source 'Text'.
--
--   * 'SubstitutedByteSequence' — decode-side: a byte sequence in
--     the wire input was not decodeable under the declared
--     encoding and was replaced with U+FFFD in the resulting
--     'Text'. The 'Int' is the 0-indexed byte offset of the
--     offending sequence within the input 'ByteString'.
--
--   * 'TruncatedToFitBound' — bounded encoding cut the source
--     off because adding the next codepoint would have overflowed
--     the byte cap. The 'OriginalLength' is the byte count the
--     source would have produced without the bound; the
--     'TruncatedLength' is what actually fit. The newtypes are
--     the same ones 'Slap.Status.FieldTruncated' carries, so a
--     call site lifting this to an advisory hands the values
--     straight through with no re-wrapping.
--
-- Substitution notices report by position so a caller can
-- describe \"event at position N\"; truncation notices report by
-- byte count because the format-level concept is "the field was
-- N bytes, we wrote M".
data LossNotice
  = SubstitutedCodepoint !Char !Int
  | SubstitutedByteSequence !Int
  | TruncatedToFitBound !OriginalLength !TruncatedLength
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- Strict primitives
----------------------------------------------------------------------------

-- | Encode 'Text' as 'ByteString' under the target encoding. Strict:
-- fails with 'Left' if any codepoint can't be represented in the
-- target, naming the first offender and its position.
--
-- 'EncodingUtf8' never fails — every Unicode codepoint has a UTF-8
-- representation, and 'Text' values are by construction Unicode.
-- 'EncodingLocale' fails when the resolved encoder reports a
-- codepoint as not 'Encoding.encodeable' under it (e.g. a Japanese
-- ideograph under a Latin-1 locale).
encodeText :: EncodingName -> Text -> Either EncodeError ByteString
encodeText EncodingUtf8 text = Right (TextEncoding.encodeUtf8 text)
encodeText EncodingLocale text =
  case findFirstUnencodeable encoder (Text.unpack text) 0 of
    Just (badChar, position) ->
      Left (EncodeError EncodingLocale badChar position)
    Nothing ->
      Right (Encoding.encodeStrictByteString encoder (Text.unpack text))
  where
    (encoder, _advisory) = processLocaleEncoder

-- | Walk a 'String' looking for the first character the encoder
-- can't represent. The library's 'Encoding.encodeable' predicate is
-- exactly the question we want answered, and asking it before calling
-- 'encodeStrictByteString' lets us pinpoint the offender — the
-- library's own exceptions don't carry a stable position field
-- across all encoders.
findFirstUnencodeable
  :: Encoding.DynEncoding -> [Char] -> Int -> Maybe (Char, Int)
findFirstUnencodeable _ [] _ = Nothing
findFirstUnencodeable enc (char : rest) position
  | Encoding.encodeable enc char = findFirstUnencodeable enc rest (position + 1)
  | otherwise                    = Just (char, position)

-- | Decode 'ByteString' as 'EncodedText' under the declared encoding.
-- Strict: fails with 'Left' if the bytes aren't valid in the
-- declared encoding. The resulting 'EncodedText' carries the same
-- encoding tag the caller supplied — the value records what slap
-- was asked to decode as, not the host-locale specifics underneath.
decodeText :: EncodingName -> ByteString -> Either DecodeError EncodedText
decodeText EncodingUtf8 bytes = case TextEncoding.decodeUtf8' bytes of
  Right text   -> Right (EncodedText EncodingUtf8 text)
  Left failure -> Left (DecodeError EncodingUtf8 (show failure))
decodeText EncodingLocale bytes =
  case Encoding.decodeStrictByteStringExplicit encoder bytes of
    Right decoded -> Right (EncodedText EncodingLocale (Text.pack decoded))
    Left failure  -> Left (DecodeError EncodingLocale (show failure))
  where
    (encoder, _advisory) = processLocaleEncoder

----------------------------------------------------------------------------
-- Lenient primitives
----------------------------------------------------------------------------

-- | Encode 'Text' under the target encoding, substituting for any
-- codepoint that the target can't represent. Always succeeds; the
-- 'LossNotice' list reports each substitution (with the substituted
-- codepoint and its source position). The substitute is U+FFFD when
-- the target represents it, @\'?\'@ otherwise.
--
-- 'EncodingUtf8' never substitutes — UTF-8 represents every Unicode
-- codepoint — so the notice list is always empty on this path.
encodeTextLenient :: EncodingName -> Text -> (ByteString, [LossNotice])
encodeTextLenient EncodingUtf8 text =
  (TextEncoding.encodeUtf8 text, [])
encodeTextLenient EncodingLocale text =
  let chars                = Text.unpack text
      substitute           = chooseSubstitute encoder
      (filtered, notices)  = substituteUnencodeable encoder substitute chars
      bytes                = Encoding.encodeStrictByteString encoder filtered
  in (bytes, notices)
  where
    (encoder, _advisory) = processLocaleEncoder

-- | Replace each character the encoder can't represent with the
-- encoder's substitute character, recording each replacement. The
-- positions in the returned notices index into the original source,
-- so a caller correlating notices back to the source 'Text' sees
-- the right offsets.
substituteUnencodeable
  :: Encoding.DynEncoding -> Char -> [Char] -> ([Char], [LossNotice])
substituteUnencodeable encoder substitute = walk 0 [] []
  where
    walk _ accChars accNotices [] =
      (reverse accChars, reverse accNotices)
    walk position accChars accNotices (char : rest)
      | Encoding.encodeable encoder char =
          walk (position + 1) (char : accChars) accNotices rest
      | otherwise =
          let notice = SubstitutedCodepoint char position
          in walk (position + 1) (substitute : accChars) (notice : accNotices) rest

-- | Pick the substitute character for an encoding. U+FFFD is the
-- Unicode replacement character and is what every modern encoder
-- that can represent it uses; for ASCII-only targets that can't
-- represent U+FFFD, the conventional fallback is @\'?\'@.
chooseSubstitute :: Encoding.DynEncoding -> Char
chooseSubstitute encoder
  | Encoding.encodeable encoder '\xFFFD' = '\xFFFD'
  | otherwise                            = '?'

-- | Decode 'ByteString' under the declared encoding, substituting
-- U+FFFD for any byte sequence that the encoding can't decode.
-- Always succeeds. Returns the decoded 'EncodedText' paired with one
-- 'SubstitutedByteSequence' notice per substitution event (each one
-- carrying the byte offset where the offending sequence began); a
-- clean decode yields an empty notice list.
--
-- Each encoding plugs its own strict-decode primitive into the
-- shared 'recoveringDecode' walk: 'EncodingUtf8' uses
-- 'TextEncoding.decodeUtf8'', 'EncodingLocale' uses the
-- locale-resolved 'Encoding.decodeStrictByteStringExplicit'. The
-- recovery shape — strict-decode first, prefix-recover on failure,
-- emit a single 'SubstitutedByteSequence' per substituted byte,
-- recurse on the rest — is identical across both. The walk is O(n)
-- on the clean path (one strict decode) and O(n²) on the failure
-- path; for slap's text fields (at most ~1 KiB) the cost is
-- imperceptible.
decodeTextLenient :: EncodingName -> ByteString -> (EncodedText, [LossNotice])
decodeTextLenient EncodingUtf8 bytes =
  let (text, notices) = recoveringDecode TextEncoding.decodeUtf8' bytes
  in (EncodedText EncodingUtf8 text, notices)
decodeTextLenient EncodingLocale bytes =
  let strictLocaleDecode = fmap Text.pack
                         . Encoding.decodeStrictByteStringExplicit encoder
      (text, notices)    = recoveringDecode strictLocaleDecode bytes
  in (EncodedText EncodingLocale text, notices)
  where
    (encoder, _advisory) = processLocaleEncoder

-- | Lenient-decode primitive parameterised over the encoding's strict
-- decoder. On strict success the whole input decodes cleanly and the
-- notice list is empty; on strict failure the walk finds the largest
-- decodeable prefix, emits its decoded text followed by U+FFFD and
-- a 'SubstitutedByteSequence' carrying the offending byte's offset,
-- and recurses on the bytes past the offending byte. The
-- @strictDecode@ parameter's 'Either' failure type is left polymorphic
-- because each backend reports decode failures with its own exception
-- type; the walk only cares about success-vs-failure, not the
-- failure's shape.
recoveringDecode
  :: (ByteString -> Either failure Text)
  -> ByteString
  -> (Text, [LossNotice])
recoveringDecode strictDecode = walkAt 0
  where
    walkAt offset bytes
      | ByteString.null bytes = (Text.empty, [])
      | otherwise = case strictDecode bytes of
          Right text   -> (text, [])
          Left _failure ->
            let prefixLength = largestValidPrefix bytes
                prefixBytes  = ByteString.take prefixLength bytes
                remainingBytes = ByteString.drop (prefixLength + 1) bytes
                prefixText   = either (const Text.empty) id
                                      (strictDecode prefixBytes)
                badByteOffset = offset + prefixLength
                (restText, restNotices) =
                  walkAt (badByteOffset + 1) remainingBytes
            in ( prefixText <> Text.singleton '\xFFFD' <> restText
               , SubstitutedByteSequence badByteOffset : restNotices )

    -- Largest prefix length that decodes cleanly. Linear walk-back
    -- from the full byte count; the empty prefix always succeeds, so
    -- this always finds at least 0.
    largestValidPrefix bytes = walkBack (ByteString.length bytes - 1)
      where
        walkBack candidate
          | candidate < 0 = 0
          | otherwise = case strictDecode (ByteString.take candidate bytes) of
              Right _ -> candidate
              Left _  -> walkBack (candidate - 1)

----------------------------------------------------------------------------
-- Bounded encoding
----------------------------------------------------------------------------

-- | Encode 'Text' under the target encoding with a byte-count cap.
-- Codepoint-aware: encodes codepoint by codepoint, stops when adding
-- the next codepoint would exceed the cap. The result is always
-- valid bytes in the target encoding (no split codepoints) and is
-- at most @cap@ bytes long.
--
-- Substitution semantics from 'encodeTextLenient' apply: codepoints
-- the target can't represent become substitutes, with each
-- substitution reported as a 'SubstitutedCodepoint' notice.
-- Truncation, if it happens, surfaces as a 'TruncatedToFitBound'
-- notice carrying the byte count the source would have produced
-- without the cap (matching 'Slap.Status.OriginalLength') and the
-- byte count actually written (matching 'TruncatedLength').
--
-- The caller decides what to do about the notices — slap's create
-- paths typically lift each one to a 'Slap.Status.FieldTruncated'
-- advisory tagged with the format and field name. Padding to the
-- format's exact field width (PPF1/PPF2's 0x20-pad,
-- PPF3/APSN64/DPS's 0x00-pad) stays at the call site; this
-- primitive does the encoding and truncation only.
encodeTextBounded :: EncodingName -> Int -> Text -> (ByteString, [LossNotice])
encodeTextBounded encodingName cap text =
  let perCodepoint = zipWith (encodeSingleCodepoint encodingName)
                             [0 ..] (Text.unpack text)
      (taken, remaining) = takeChunksUnderCap cap perCodepoint
      takenBytes         = ByteString.concat (map fst taken)
      substitutionNotes  = mapMaybe snd taken
      truncationNotes    = case remaining of
        [] -> []
        _  -> let writtenBytes  = ByteString.length takenBytes
                  originalBytes = writtenBytes
                                + sum (map (ByteString.length . fst) remaining)
              in [TruncatedToFitBound
                    (OriginalLength  (Length originalBytes))
                    (TruncatedLength (Length writtenBytes))]
  in (takenBytes, substitutionNotes ++ truncationNotes)

-- | Encode a single codepoint under the target encoding, returning
-- the bytes plus an optional substitution notice. UTF-8 always
-- represents the codepoint and never substitutes; locale paths
-- substitute when the encoder can't represent the codepoint and
-- report the substitution at the codepoint's source position.
encodeSingleCodepoint
  :: EncodingName -> Int -> Char -> (ByteString, Maybe LossNotice)
encodeSingleCodepoint EncodingUtf8 _position char =
  (TextEncoding.encodeUtf8 (Text.singleton char), Nothing)
encodeSingleCodepoint EncodingLocale position char =
  let (encoder, _advisory) = processLocaleEncoder
  in if Encoding.encodeable encoder char
       then (Encoding.encodeStrictByteString encoder [char], Nothing)
       else let substitute = chooseSubstitute encoder
                bytes      = Encoding.encodeStrictByteString encoder [substitute]
            in (bytes, Just (SubstitutedCodepoint char position))

-- | Walk a list of per-codepoint encoded chunks, accumulating until
-- the next chunk would push the running byte count past the cap.
-- Returns the prefix that fit and the suffix that didn't, so the
-- caller can compute the truncated byte count and the would-be
-- original count in one walk.
takeChunksUnderCap
  :: Int
  -> [(ByteString, a)]
  -> ([(ByteString, a)], [(ByteString, a)])
takeChunksUnderCap cap = walk 0 []
  where
    walk _    takenReversed [] = (reverse takenReversed, [])
    walk used takenReversed (chunk@(bytes, _) : rest) =
      let nextUsed = used + ByteString.length bytes
      in if nextUsed > cap
           then (reverse takenReversed, chunk : rest)
           else walk nextUsed (chunk : takenReversed) rest

----------------------------------------------------------------------------
-- Advisory adaptation
----------------------------------------------------------------------------

-- | Adapt the substitution notices a 'decodeTextLenient' call emitted
-- into 'SlapAdvisory' values tagged with the format and field. The
-- per-byte position detail is folded down to a single substitution
-- count: at the advisory layer the user wants to know that the field
-- had unrepresentable bytes and how many, not where each one sat.
-- A clean decode (empty notice list) yields an empty advisory list.
decodeLossAdvisories
  :: FormatLabel -> FieldName -> [LossNotice] -> [SlapAdvisory]
decodeLossAdvisories label field notices =
  let substitutions = length [() | SubstitutedByteSequence{} <- notices]
  in [FieldDecodedSubstituted label field (SubstitutionCount substitutions)
      | substitutions > 0]

-- | Adapt the loss notices an 'encodeTextLenient' or 'encodeTextBounded'
-- call emitted into 'SlapAdvisory' values tagged with the format and
-- field. Substitution notices fold to a single 'FieldEncodedSubstituted'
-- carrying the count; a 'TruncatedToFitBound' notice (only produced by
-- the bounded path) lifts to 'FieldTruncated' with the same byte
-- counts. Either kind, or both, can fire from one call.
encodeLossAdvisories
  :: FormatLabel -> FieldName -> [LossNotice] -> [SlapAdvisory]
encodeLossAdvisories label field notices =
  let substitutions = length [() | SubstitutedCodepoint{} <- notices]
      substitutionAdvisory =
        [FieldEncodedSubstituted label field (SubstitutionCount substitutions)
         | substitutions > 0]
      truncationAdvisories =
        [FieldTruncated label field original truncated
         | TruncatedToFitBound original truncated <- notices]
  in substitutionAdvisory ++ truncationAdvisories

----------------------------------------------------------------------------
-- Locale resolution
----------------------------------------------------------------------------

-- | The resolved encoder for the @EncodingLocale@ tag, paired with
-- an optional advisory naming the unresolved locale if the lookup
-- failed and slap fell back to UTF-8.
--
-- Computed once at module init via 'unsafePerformIO' + @NOINLINE@.
-- Reads the running process locale via 'getLocaleEncoding', extracts
-- the encoding name, and asks the @encoding@ library to resolve it
-- via 'Encoding.encodingFromStringExplicit'. The resolver tries the
-- name as reported, a few case-and-separator normalization variants,
-- and the curated 'documentedLocaleAliases' table.
--
-- The advisory channel is value-based: callers that want to surface
-- the locale-unresolved condition destructure the pair and route
-- the @Just@ through their own pipeline. The resolver itself does
-- not emit; it just makes the signal available.
processLocaleEncoder :: (Encoding.DynEncoding, Maybe SlapAdvisory)
processLocaleEncoder = unsafePerformIO $ do
  localeName <- textEncodingName <$> getLocaleEncoding
  pure $ case resolveEncoderByName localeName of
    Just resolved -> (resolved, Nothing)
    Nothing       ->
      let utf8Fallback = Encoding.encodingFromString "UTF-8"
      in (utf8Fallback, Just (LocaleEncoderUnresolved localeName))
{-# NOINLINE processLocaleEncoder #-}

-- | Try the @encoding@ library's lookup against the given locale
-- name and a small set of normalization variants. The first variant
-- that resolves wins; if all fail, returns 'Nothing'. Variants
-- handle case differences, dash\/underscore variations, and the
-- common Windows codepage names that GHC reports as @CPnnnn@.
resolveEncoderByName :: String -> Maybe Encoding.DynEncoding
resolveEncoderByName name = foldr (<|>) Nothing
  [ Encoding.encodingFromStringExplicit variant
  | variant <- localeNameVariants name
  ]

-- | Normalization variants of a locale encoding name. Tried in
-- order against 'Encoding.encodingFromStringExplicit'; the first
-- variant that resolves is what we use.
--
-- Two tiers: first the case\/separator normalizations (handle the
-- @ISO-8859-1@ vs @iso88591@ vs @ISO_8859_1@ family without
-- committing to a curated alias table), then the
-- 'documentedLocaleAliases' table for the named locale shapes
-- GHC reports on Windows hosts and on non-UTF-8 Unix locales.
-- Alias-table entries are tried before their cousin fallbacks,
-- so a library version that recognizes the locale's preferred
-- name directly skips the substitution.
localeNameVariants :: String -> [String]
localeNameVariants name =
  [ name
  , map toUpper name
  , map toLower name
  , stripDashesUnderscores name
  , stripDashesUnderscores (map toUpper name)
  , stripDashesUnderscores (map toLower name)
  ]
  ++ documentedLocaleAliases name

-- | Strip @-@ and @_@ from a name, leaving alphanumeric. Lets
-- @ISO-8859-1@ match @iso88591@-style aliases, @Shift_JIS@ match
-- @shiftjis@, etc.
stripDashesUnderscores :: String -> String
stripDashesUnderscores = filter (\c -> c /= '-' && c /= '_')

-- | Curated alias table mapping the names GHC's 'getLocaleEncoding'
-- might report on a Windows host or a non-UTF-8 Unix locale to a
-- list of names to try against the @encoding@ library. Three
-- categories of entry:
--
--   * /Direct/ — the @encoding@ library ships an encoder under the
--     mapped name. The Windows codepage family, the DOS\/OEM
--     codepages, Cyrillic KOI8-R\/U, the Japanese standards
--     (Shift-JIS, ISO-2022-JP), and the Chinese GB18030 standard
--     are in this category. Uses the library's own name, so the
--     decode is exact: every byte sequence the source codepage
--     defines decodes to the codepoint the codepage spec assigns.
--
--   * /Compatible superset/ — the @encoding@ library doesn't ship
--     the exact codepage but does ship a strictly compatible
--     superset. Microsoft's CP936 (Simplified Chinese) maps to
--     GB18030, which is documented to be a strict byte-level
--     superset of GBK (and GB2312); any valid CP936 byte sequence
--     decodes identically under GB18030. Microsoft's CP1250-1257
--     fall back to the matching ISO-8859 variant where the
--     codepage entry isn't recognized; the ISO cousins are
--     ASCII-clean and differ only in upper-half glyphs (e.g.
--     CP1252's @\\x80@ Euro sign vs ISO-8859-1's @\\x80@ control
--     character).
--
--   * /Documented gap/ — the @encoding@ library doesn't ship an
--     encoder and there's no compatible superset in the library.
--     The entry has an empty list, so the lookup falls through to
--     'LocaleEncoderUnresolved' and the user sees an honest
--     advisory rather than mojibake from a near-miss decoder.
--     Listed by name so a future-self reading the code sees the
--     locale was considered. Korean Wansung (CP949), Big5 (CP950
--     and the bare-name variants), the EUC-* family, TIS-620
--     (Thai), VISCII and TCVN (Vietnamese), ARMSCII-8 (Armenian),
--     and TSCII (Tamil) all sit here. Closing any of them needs
--     either a backend swap (@text-icu@ against ICU4C covers all
--     of these) or a hand-rolled decoder. The table documents the
--     gap so the cost of closing it is visible.
--
-- Mappings come from Microsoft's codepage-to-charset tables and
-- IANA's character-set registry. They have not been exercised
-- under each target locale on a real host, so the documented-but-
-- untested caveat applies. Drift in the upper-half byte ranges
-- between a Microsoft codepage and its ISO cousin is the failure
-- mode to watch for; ASCII text and text whose upper-half
-- characters are well-defined in the cousin will round-trip
-- correctly.
--
-- The table is keyed on the @uppercase + dashes-and-underscores-
-- stripped@ form of the locale name, so @cp1252@, @CP-1252@,
-- @CP_1252@, @Shift_JIS@, @shift-jis@, and @SHIFTJIS@ all reach
-- the same arm.
documentedLocaleAliases :: String -> [String]
documentedLocaleAliases name = case normalizeForLookup name of

  -- Unicode locale names
  "CP65001"   -> ["UTF-8"]
  "UTF8"      -> ["UTF-8"]
  "UTF16"     -> ["UTF-16"]
  "UTF32"     -> ["UTF-32"]

  -- Windows codepages: Western / European / Mediterranean
  "CP1250"    -> ["CP1250", "ISO-8859-2"]      -- Central European
  "CP1251"    -> ["CP1251", "ISO-8859-5"]      -- Cyrillic
  "CP1252"    -> ["CP1252", "ISO-8859-1"]      -- Western European
  "CP1253"    -> ["CP1253", "ISO-8859-7"]      -- Greek
  "CP1254"    -> ["CP1254", "ISO-8859-9"]      -- Turkish
  "CP1255"    -> ["CP1255", "ISO-8859-8"]      -- Hebrew
  "CP1256"    -> ["CP1256", "ISO-8859-6"]      -- Arabic
  "CP1257"    -> ["CP1257", "ISO-8859-13"]     -- Baltic (8859-13, not 8859-4)
  "CP1258"    -> ["CP1258"]                    -- Vietnamese (library has it directly)

  -- Windows codepages: East Asian
  "CP932"     -> ["CP932", "Shift-JIS"]        -- Japanese (MS Shift-JIS + NEC/IBM ext.)
  "CP936"     -> ["GB18030"]                   -- Simplified Chinese (GBK ⊂ GB18030)

  -- DOS / OEM codepages
  "CP437"     -> ["CP437"]                     -- Original IBM PC (United States)
  "CP737"     -> ["CP737"]                     -- DOS Greek
  "CP775"     -> ["CP775"]                     -- DOS Baltic Rim
  "CP850"     -> ["CP850"]                     -- DOS Western European
  "CP852"     -> ["CP852"]                     -- DOS Central European
  "CP855"     -> ["CP855"]                     -- DOS Cyrillic
  "CP857"     -> ["CP857"]                     -- DOS Turkish
  "CP860"     -> ["CP860"]                     -- DOS Portuguese
  "CP861"     -> ["CP861"]                     -- DOS Icelandic
  "CP862"     -> ["CP862"]                     -- DOS Hebrew
  "CP863"     -> ["CP863"]                     -- DOS Canadian French
  "CP864"     -> ["CP864"]                     -- DOS Arabic
  "CP865"     -> ["CP865"]                     -- DOS Nordic
  "CP866"     -> ["CP866"]                     -- DOS Russian Cyrillic
  "CP869"     -> ["CP869"]                     -- DOS Modern Greek
  "CP874"     -> ["CP874"]                     -- Thai (DOS + Windows)

  -- Cyrillic Unix locales
  "KOI8R"     -> ["KOI8-R"]                    -- Russian
  "KOI8U"     -> ["KOI8-U"]                    -- Ukrainian
  "KOI8"      -> ["KOI8-R"]                    -- bare KOI8 → Russian variant

  -- macOS Classic. The encoding library's matched name is
  -- @macintosh@ (the IANA-registered charset name), not
  -- @MacOSRoman@ — that's the library's module name only.
  "MAC"       -> ["macintosh"]
  "MACINTOSH" -> ["macintosh"]
  "MACROMAN"  -> ["macintosh"]

  -- Japanese Unix-shape names. The encoding library accepts both
  -- @Shift-JIS@ (it normalizes to @shift_jis@ internally) and the
  -- bare @sjis@ alias.
  "SJIS"      -> ["Shift-JIS"]
  "SHIFTJIS"  -> ["Shift-JIS"]
  "ISO2022JP" -> ["ISO-2022-JP"]

  -- Chinese Unix-shape names (GB18030 covers GBK and GB2312)
  "GB18030"   -> ["GB18030"]
  "GBK"       -> ["GB18030"]                   -- GBK ⊂ GB18030
  "GB2312"    -> ["GB18030"]                   -- GB2312 ⊂ GBK ⊂ GB18030

  -- Documented gaps — the encoding library doesn't ship an encoder
  -- and there's no compatible superset. Empty list; the lookup
  -- falls through to LocaleEncoderUnresolved and the user sees an
  -- honest advisory. Closing any of these needs a different
  -- encoding backend (text-icu) or a hand-rolled decoder.
  "CP949"     -> []                            -- CP949 (Windows Korean Wansung)
  "CP950"     -> []                            -- CP950 (Windows Big5)
  "EUCJP"     -> []                            -- EUC-JP (Japanese)
  "EUCKR"     -> []                            -- EUC-KR (Korean)
  "EUCCN"     -> []                            -- EUC-CN (Simplified Chinese)
  "EUCTW"     -> []                            -- EUC-TW (Traditional Chinese)
  "BIG5"      -> []                            -- Big5 (Traditional Chinese)
  "BIG5HKSCS" -> []                            -- Big5 + Hong Kong Supplementary Character Set
  "TIS620"    -> []                            -- TIS-620 (Thai; differs from CP874 in the upper half)
  "VISCII"    -> []                            -- VISCII (Vietnamese)
  "TCVN"      -> []                            -- TCVN5712 (Vietnamese)
  "ARMSCII8"  -> []                            -- ARMSCII-8 (Armenian)
  "TSCII"     -> []                            -- TSCII (Tamil)

  _           -> []
  where
    normalizeForLookup = map toUpper . filter (\c -> c /= '-' && c /= '_')
