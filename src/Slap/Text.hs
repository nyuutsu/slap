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
-- Plus 'resolveEncodingName', which turns a user-supplied encoding
-- name into a 'NamedEncoding' the 'EncodingNamed' tag carries (see
-- below).
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
-- == The name resolver
--
-- 'EncodingNamed' carries a 'NamedEncoding': a user-facing encoding
-- name paired with the @encoding@-library encoder it resolved to.
-- 'resolveEncodingName' is the only way to build one — it feeds the
-- name through the resolution engine (case- and separator-
-- normalization variants, then the curated 'documentedLocaleAliases'
-- table) and returns 'Left' 'UnresolvableEncodingName' for a name the
-- library can't place. The name slap resolves is one it was handed
-- (today, the @--metadata-encoding@ CLI value), no longer one read
-- from the environment; a resolution failure is the caller's to
-- surface, not a silent fallback.
--
-- == What the encoding tag remembers
--
-- When 'decodeText' produces an 'EncodedText', the tag is the
-- encoding the caller asked slap to decode as. For 'EncodingNamed'
-- the 'NamedEncoding' carries the resolved encoder directly, so a
-- later 'encodeText' or 'encodeTextLenient' under the same tag routes
-- through that same encoder. The name-to-encoder decision was made
-- once, at resolution time, and travels with the value rather than
-- being re-derived at each transcode site.
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

    -- * Named-encoding resolution
  , NamedEncoding
  , resolveEncodingName
  , displayNamedEncoding
  , useNamedEncoding
  , UnresolvableEncodingName(..)

    -- * Advisory adaptation
  , decodeLossAdvisories
  , encodeLossAdvisories

    -- * Advertised encoding set
  , AdvertisedEncodingFamily(..)
  , advertisedEncodings
  , advertisedEncodingNames
  , renderAdvertisedEncodings
  ) where

import Control.Applicative ((<|>))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower, toUpper)
import Data.List (intercalate)
import qualified Data.Encoding as Encoding
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding
import Slap.FieldName (FieldName)
import Slap.FormatLabel (FormatLabel)
import Slap.Measure (Length(..), OriginalLength(..), TruncatedLength(..),
                     SubstitutionCount(..))
import Slap.Status (SlapAdvisory(..))

----------------------------------------------------------------------------
-- Tag
----------------------------------------------------------------------------

-- | Which encoding a text value's bytes are in (or are to be
-- interpreted as). 'EncodingUtf8' is the well-defined Unicode case,
-- routed through the @text@ package's fast native codec.
-- 'EncodingNamed' carries any other encoding slap was asked to use —
-- a 'NamedEncoding' resolved from a user-supplied name through the
-- @encoding@ library (Shift-JIS, CP1252, KOI8-R, and the rest of the
-- 'documentedLocaleAliases' table).
data EncodingName
  = EncodingUtf8
  | EncodingNamed NamedEncoding
  deriving (Eq, Show)

-- | A resolved encoding: the user-facing name slap was handed paired
-- with the @encoding@-library encoder it resolved to. Constructable
-- only through 'resolveEncodingName', so a 'NamedEncoding' in hand is
-- always a name that resolved — there is no way to hold one whose
-- name and encoder disagree.
--
-- The type is identified by its name. The smart constructor makes the
-- encoder a function of the name (equal names resolve to equal
-- encoders), so the hand-written 'Eq' over the name alone is exactly
-- a derived 'Eq', and 'Show' reads as the encoding's name rather than
-- dumping the library's internal 'Encoding.DynEncoding'.
data NamedEncoding = NamedEncoding
  { namedEncodingDisplay  :: !Text
  , namedEncodingResolved :: !Encoding.DynEncoding
  }

instance Eq NamedEncoding where
  left == right = namedEncodingDisplay left == namedEncodingDisplay right

instance Show NamedEncoding where
  show = Text.unpack . namedEncodingDisplay

-- | The user-facing name a 'NamedEncoding' was resolved from.
displayNamedEncoding :: NamedEncoding -> Text
displayNamedEncoding = namedEncodingDisplay

-- | The resolved @encoding@-library encoder a 'NamedEncoding' carries.
useNamedEncoding :: NamedEncoding -> Encoding.DynEncoding
useNamedEncoding = namedEncodingResolved

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
-- 'EncodingNamed' fails when the resolved encoder reports a codepoint
-- as not 'Encoding.encodeable' under it (e.g. a Japanese ideograph
-- under a Latin-1 encoding).
encodeText :: EncodingName -> Text -> Either EncodeError ByteString
encodeText EncodingUtf8 text = Right (TextEncoding.encodeUtf8 text)
encodeText (EncodingNamed named) text =
  case findFirstUnencodeable encoder (Text.unpack text) 0 of
    Just (badChar, position) ->
      Left (EncodeError (EncodingNamed named) badChar position)
    Nothing ->
      Right (Encoding.encodeStrictByteString encoder (Text.unpack text))
  where
    encoder = useNamedEncoding named

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
decodeText (EncodingNamed named) bytes =
  case Encoding.decodeStrictByteStringExplicit encoder bytes of
    Right decoded -> Right (EncodedText (EncodingNamed named) (Text.pack decoded))
    Left failure  -> Left (DecodeError (EncodingNamed named) (show failure))
  where
    encoder = useNamedEncoding named

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
encodeTextLenient (EncodingNamed named) text =
  let chars                = Text.unpack text
      substitute           = chooseSubstitute encoder
      (filtered, notices)  = substituteUnencodeable encoder substitute chars
      bytes                = Encoding.encodeStrictByteString encoder filtered
  in (bytes, notices)
  where
    encoder = useNamedEncoding named

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
-- 'TextEncoding.decodeUtf8'', 'EncodingNamed' uses the resolved
-- encoder's 'Encoding.decodeStrictByteStringExplicit'. The
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
decodeTextLenient (EncodingNamed named) bytes =
  let strictNamedDecode = fmap Text.pack
                        . Encoding.decodeStrictByteStringExplicit encoder
      (text, notices)   = recoveringDecode strictNamedDecode bytes
  in (EncodedText (EncodingNamed named) text, notices)
  where
    encoder = useNamedEncoding named

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
-- represents the codepoint and never substitutes; a named encoding
-- substitutes when its encoder can't represent the codepoint and
-- reports the substitution at the codepoint's source position.
encodeSingleCodepoint
  :: EncodingName -> Int -> Char -> (ByteString, Maybe LossNotice)
encodeSingleCodepoint EncodingUtf8 _position char =
  (TextEncoding.encodeUtf8 (Text.singleton char), Nothing)
encodeSingleCodepoint (EncodingNamed named) position char =
  let encoder = useNamedEncoding named
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
-- Name resolution
----------------------------------------------------------------------------

-- | The name handed to 'resolveEncodingName' that the resolution
-- engine couldn't place. Carries the offending name verbatim so the
-- boundary can name it back to the user.
newtype UnresolvableEncodingName = UnresolvableEncodingName
  { unresolvableEncodingName :: Text }
  deriving (Eq, Show)

-- | Resolve a user-supplied encoding name into a 'NamedEncoding', or
-- refuse with the name that didn't resolve. The resolution engine
-- ('resolveEncoderByName') tries the name as given, a few case- and
-- separator-normalization variants, and the curated
-- 'documentedLocaleAliases' table; the first that the @encoding@
-- library recognizes wins. The 'Right' is the only constructor for a
-- 'NamedEncoding', so a resolved name and its encoder can never drift
-- apart.
resolveEncodingName :: Text -> Either UnresolvableEncodingName NamedEncoding
resolveEncodingName name = case resolveEncoderByName (Text.unpack name) of
  Just encoder -> Right (NamedEncoding name encoder)
  Nothing      -> Left (UnresolvableEncodingName name)

-- | Try the @encoding@ library's lookup against the given encoding
-- name and a small set of normalization variants. The first variant
-- that resolves wins; if all fail, returns 'Nothing'. Variants
-- handle case differences, dash\/underscore variations, and the
-- common Windows codepage names spelled as @CPnnnn@.
resolveEncoderByName :: String -> Maybe Encoding.DynEncoding
resolveEncoderByName name = foldr (<|>) Nothing
  [ Encoding.encodingFromStringExplicit variant
  | variant <- localeNameVariants name
  ]

-- | Normalization variants of an encoding name. Tried in order
-- against 'Encoding.encodingFromStringExplicit'; the first variant
-- that resolves is what we use.
--
-- Two tiers: first the case\/separator normalizations (handle the
-- @ISO-8859-1@ vs @iso88591@ vs @ISO_8859_1@ family without
-- committing to a curated alias table), then the
-- 'documentedLocaleAliases' table for the named locale-style shapes
-- a Windows host or non-UTF-8 Unix locale spells. Alias-table entries
-- are tried before their cousin fallbacks, so a library version that
-- recognizes the preferred name directly skips the substitution.
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

-- | Curated alias table mapping the locale-style names a user might
-- supply (the names a Windows host or non-UTF-8 Unix locale spells)
-- to a list of names to try against the @encoding@ library. Three
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
--     The entry has an empty list, so the lookup fails and
--     'resolveEncodingName' returns 'Left' rather than mojibake from
--     a near-miss decoder. Listed by name so a future-self reading
--     the code sees the encoding was considered. Korean Wansung
--     (CP949), Big5 (CP950
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
  -- and there's no compatible superset. Empty list; the lookup fails
  -- and resolveEncodingName returns Left. Closing any of these needs
  -- a different encoding backend (text-icu) or a hand-rolled decoder.
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

----------------------------------------------------------------------------
-- Advertised encoding set
----------------------------------------------------------------------------

-- | A family of related text encodings, used only to group the set
-- @--encodings@ prints and shell completion offers. Purely
-- presentational; every member name resolves through
-- 'resolveEncodingName' (the @advertised-set-all-resolve@ case in
-- "Props.Text" guards that, so the advertised list can never promise a
-- name the bundled library won't take).
data AdvertisedEncodingFamily = AdvertisedEncodingFamily
  { advertisedFamilyLabel   :: !String
  , advertisedFamilyMembers :: ![String]
  }
  deriving (Eq, Show)

-- | Every text encoding slap decodes, one canonical name per encoder,
-- grouped for a legible @--encodings@ listing. This is the full set the
-- bundled @encoding@ library provides as field encodings, not a curated
-- subset: if a name is missing here, slap genuinely cannot decode it.
-- slap additionally /accepts/ alternate spellings of these (case- and
-- separator-insensitive, plus the 'documentedLocaleAliases' locale
-- names), but each encoder appears here exactly once. The library's
-- non-field internals — raw JIS X 0201\/0208\/0212, bare ISO-2022, and
-- punycode — are deliberately omitted; they aren't sensible encodings
-- to tag a metadata text field as.
advertisedEncodings :: [AdvertisedEncodingFamily]
advertisedEncodings =
  [ AdvertisedEncodingFamily "Unicode"   ["utf-8", "utf-16", "utf-32"]
  , AdvertisedEncodingFamily "ISO 8859"  ["iso-8859-1", "iso-8859-2", "iso-8859-3", "iso-8859-4", "iso-8859-5", "iso-8859-6", "iso-8859-7", "iso-8859-8", "iso-8859-9", "iso-8859-10", "iso-8859-11", "iso-8859-13", "iso-8859-14", "iso-8859-15", "iso-8859-16"]
  , AdvertisedEncodingFamily "Windows"   ["cp1250", "cp1251", "cp1252", "cp1253", "cp1254", "cp1255", "cp1256", "cp1257", "cp1258"]
  , AdvertisedEncodingFamily "DOS / OEM" ["cp437", "cp737", "cp775", "cp850", "cp852", "cp855", "cp857", "cp860", "cp861", "cp862", "cp863", "cp864", "cp865", "cp866", "cp869", "cp874"]
  , AdvertisedEncodingFamily "Japanese"  ["shift-jis", "cp932", "iso-2022-jp"]
  , AdvertisedEncodingFamily "Chinese"   ["gb18030"]
  , AdvertisedEncodingFamily "Cyrillic"  ["koi8-r", "koi8-u"]
  , AdvertisedEncodingFamily "Other"     ["macintosh", "ascii"]
  ]

-- | Every advertised encoding name, flattened — the candidate list for
-- shell completion of @--metadata-encoding@.
advertisedEncodingNames :: [String]
advertisedEncodingNames = concatMap advertisedFamilyMembers advertisedEncodings

-- | The @--encodings@ listing: the advertised set, one family per line
-- with labels aligned, prefaced by a note that the accepted set is
-- wider and platform-independent.
renderAdvertisedEncodings :: String
renderAdvertisedEncodings =
  unlines (headerLines ++ concatMap renderFamily advertisedEncodings)
  where
    headerLines =
      [ "Text encodings slap decodes (pass one to --metadata-encoding; default utf-8)."
      , "Names match case- and separator-insensitively, and common aliases (latin1,"
      , "sjis, windows-1252, ...) resolve too. Decoded natively, identically on every"
      , "platform."
      , ""
      ]
    -- Each family is a heading line, then its members indented beneath —
    -- so the category never reads as if it were itself an encoding name.
    renderFamily encodingFamily =
      [ "  " ++ advertisedFamilyLabel encodingFamily ++ ":"
      , "      " ++ intercalate "  " (advertisedFamilyMembers encodingFamily)
      ]
