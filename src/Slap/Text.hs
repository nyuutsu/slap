{-# LANGUAGE DerivingVia #-}

-- | Typed text values that carry their own encoding.
-- The encoding decision lives in the value itself, not in which function the call site happens to reach for.
--
-- An 'EncodedText' bundles an 'EncodingName' tag with a 'Text' payload.
-- The tag remembers what encoding the bytes were when they arrived (or what encoding slap is asked to interpret them as);
-- the 'Text' payload is the in-memory canonical form, codepoints, encoding-independent.
-- Transcoding becomes principled: convert between encodings by routing the payload through 'encodeText' or 'encodeTextLenient' under a different tag,
-- with the loss semantics of the conversion surfaced via 'LossNotice'.
--
-- == Module surface
--
-- The primitives split three ways, by what the call site needs:
--
--   * 'encodeText' / 'decodeText' — strict: for when a codepoint or byte that doesn't fit should stop the operation.
--   * 'encodeTextLenient' / 'decodeTextLenient' — lenient: for when the operation must proceed, each loss reported as a 'LossNotice'.
--   * 'encodeTextBounded' — bounded: for when the wire gives the field a fixed byte width.
--
-- == UTF-8 vs everything-else asymmetry
--
-- The UTF-8 path routes through 'Data.Text.Encoding' — the @text@ package's native fast UTF-8 codec.
-- Every other encoding routes through the @encoding@ library (@Data.Encoding@).
-- @text@ ships a fast UTF-8 codec but only UTF-8;
-- @encoding@ ships the structured API that 'encodeTextLenient' and 'encodeTextBounded' need:
-- a per-character 'encodeable' predicate, exception-aware @Explicit@ variants, and alias-table lookup via 'encodingFromString'.
--
-- == Named-encoding resolution
--
-- 'resolveEncodingName' is the only way to build the 'NamedEncoding' an 'EncodingNamed' tag carries:
-- a user-facing name paired with the encoder it resolved to.
-- It feeds the name through case- and separator-normalization variants, then the curated 'documentedLocaleAliases' table,
-- and refuses with 'Left' 'UnresolvableEncodingName' for a name the library can't place.
-- The name is one slap was handed (today, the @--metadata-encoding@ CLI value),
-- so a resolution failure is the caller's to surface, not a silent fallback.
-- A later encode under the same tag routes through the same resolved encoder:
-- the decision was made once, at resolution time, and travels with the value.
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

    -- * Substitution measurement
  , substitutionCount

    -- * Bounded encoding (fixed-width fields)
  , encodeTextBounded

    -- * Fixed-width field reading
  , FieldContent(..)
  , readFixedWidthTextField
  , decodeFixedWidthTextField

    -- * Named-encoding resolution
  , NamedEncoding
  , resolveEncodingName
  , displayNamedEncoding
  , encodingDisplayName
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
import Data.Aeson (ToJSON(..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower, toUpper)
import Data.List (intercalate)
import Data.Encoding (DynEncoding)
import qualified Data.Encoding as Encoding
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding
import GHC.Generics (Generic, Generically(..))
import Slap.FieldName (FieldName)
import Slap.FormatLabel (FormatLabel)
import Slap.Measure (Length(..), OriginalLength(..), TruncatedLength(..),
                     SubstitutionCount(..), byteLength)
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

-- | A resolved encoding: the user-facing name slap was handed, paired with the @encoding@-library encoder it resolved to.
-- Constructable only through 'resolveEncodingName', so name and encoder can never disagree.
--
-- The type is identified by its name: the smart constructor makes the encoder a function of the name (equal names resolve to equal encoders),
-- so the hand-written 'Eq' over the name alone is exactly a derived 'Eq',
-- and 'Show' reads as the encoding's name rather than dumping the library's internal 'DynEncoding'.
data NamedEncoding = NamedEncoding
  { namedEncodingDisplay  :: !Text
  , namedEncodingResolved :: !DynEncoding
  }

instance Eq NamedEncoding where
  left == right = namedEncodingDisplay left == namedEncodingDisplay right

instance Show NamedEncoding where
  show = Text.unpack . namedEncodingDisplay

-- | The user-facing name a 'NamedEncoding' was resolved from.
displayNamedEncoding :: NamedEncoding -> Text
displayNamedEncoding = namedEncodingDisplay

-- | A user-facing name for any 'EncodingName' — @"utf8"@ for the
-- well-defined Unicode case, the resolved-from name for a
-- 'EncodingNamed'. For messages that need to say which encoding bytes
-- were read through.
encodingDisplayName :: EncodingName -> Text
encodingDisplayName EncodingUtf8          = Text.pack "utf8"
encodingDisplayName (EncodingNamed named) = displayNamedEncoding named

-- | Crosses a JSON boundary as its display name: the encoder half of a 'NamedEncoding' is a resolved dictionary, not data.
instance ToJSON EncodingName where
  toJSON     = toJSON . encodingDisplayName
  toEncoding = toEncoding . encodingDisplayName

-- | The resolved @encoding@-library encoder a 'NamedEncoding' carries.
useNamedEncoding :: NamedEncoding -> DynEncoding
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
  } deriving (Eq, Show, Generic)
    deriving (ToJSON) via Generically EncodedText

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

-- | What got lost when a lenient encode, lenient decode, or bounded encode finished without a 'Left'. Three cases:
--
--   * 'SubstitutedCodepoint' — encode-side: a codepoint the target encoding cannot represent,
--     replaced with its substitute (U+FFFD, or @\'?\'@ if the target lacks it).
--   * 'SubstitutedByteSequence' — decode-side: a byte sequence the declared encoding cannot decode, replaced with U+FFFD.
--   * 'TruncatedToFitBound' — bounded encoding stopped before a codepoint that would overflow the byte cap.
--     The 'OriginalLength' and 'TruncatedLength' are the unbounded and written byte counts, the newtypes 'Slap.Status.FieldTruncated' carries.
--
-- The substitution cases carry nothing; a caller only counts them.
-- Truncation carries its byte counts, which the advisory reports.
data LossNotice
  = SubstitutedCodepoint
  | SubstitutedByteSequence
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
-- representation, and 'Text' values are Unicode.
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
  :: DynEncoding -> [Char] -> Int -> Maybe (Char, Int)
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

-- | Replace each character the encoder can't represent with its substitute, one 'SubstitutedCodepoint' per replacement.
substituteUnencodeable
  :: DynEncoding -> Char -> [Char] -> ([Char], [LossNotice])
substituteUnencodeable encoder substitute chars =
  (map fst stepped, mapMaybe snd stepped)
  where
    stepped = map substituteChar chars
    substituteChar char
      | Encoding.encodeable encoder char = (char, Nothing)
      | otherwise                        = (substitute, Just SubstitutedCodepoint)

-- | The Unicode replacement character (U+FFFD).
replacementCharacter :: Char
replacementCharacter = '\xFFFD'

-- | The substitute character for an encoding: 'replacementCharacter' where the target can represent it, else @\'?\'@ for an ASCII-only target.
chooseSubstitute :: DynEncoding -> Char
chooseSubstitute encoder
  | Encoding.encodeable encoder replacementCharacter = replacementCharacter
  | otherwise                                        = '?'

-- | Decode 'ByteString' under the declared encoding, substituting U+FFFD for any bytes it can't decode.
-- Always succeeds: a clean decode yields no notices, and each substitution adds a 'SubstitutedByteSequence' the caller counts.
--
-- 'EncodingUtf8' decodes leniently through the @text@ package; 'EncodingNamed' through 'recoverNamed'.
decodeTextLenient :: EncodingName -> ByteString -> (EncodedText, [LossNotice])
decodeTextLenient EncodingUtf8 bytes = case TextEncoding.decodeUtf8' bytes of
  Right text -> (EncodedText EncodingUtf8 text, [])
  Left _     ->
    -- Counts U+FFFD in the output, so an input that itself encodes one inflates the tally — harmless for a lossiness count.
    let text          = TextEncoding.decodeUtf8Lenient bytes
        substitutions = Text.count (Text.singleton replacementCharacter) text
    in (EncodedText EncodingUtf8 text, replicate substitutions SubstitutedByteSequence)
decodeTextLenient (EncodingNamed named) bytes =
  let (text, notices) = recoverNamed (useNamedEncoding named) bytes
  in (EncodedText (EncodingNamed named) text, notices)

substitutionCount :: [LossNotice] -> SubstitutionCount
substitutionCount notices = SubstitutionCount (length [() | SubstitutedByteSequence <- notices])

-- | Lenient decode for a named encoding, recovering over the @encoding@ library's strict, all-or-nothing decode.
-- The walk is backward because no forward decode fits: @decodeChar@ loses ISO-2022-JP's charset state between characters,
-- and driving the codec through @Data.Binary.Get@ reports a position but throws a bad byte as a pure exception, uncatchable as a value.
-- Only a whole-buffer decode catches the bad byte, and it does not say where — so we probe for the boundary. O(n²).
recoverNamed :: DynEncoding -> ByteString -> (Text, [LossNotice])
recoverNamed encoder = recover
  where
    strictDecode = fmap Text.pack . Encoding.decodeStrictByteStringExplicit encoder
    recover bytes
      | ByteString.null bytes = (Text.empty, [])
      | otherwise = case strictDecode bytes of
          Right text -> (text, [])
          -- The exception names the bad byte but not where — nothing usable here, which is why we probe.
          Left _ ->
            let (prefixLength, prefixText) = longestDecodablePrefix bytes
                -- Resume past the one undecodable byte (now U+FFFD); dropping it is the recursion's progress.
                (restText, restNotices) = recover (ByteString.drop (prefixLength + 1) bytes)
            in (prefixText <> Text.singleton replacementCharacter <> restText, SubstitutedByteSequence : restNotices)

    -- The longest prefix that decodes, with its text; walked back a byte at a time from just under the full length.
    longestDecodablePrefix bytes = walkBack (ByteString.length bytes - 1)
      where
        walkBack candidate
          | candidate == 0 = (0, Text.empty)   -- walked to the front: no non-empty prefix decoded
          | otherwise = case strictDecode (ByteString.take candidate bytes) of
              Right text -> (candidate, text)
              Left _     -> walkBack (candidate - 1)

----------------------------------------------------------------------------
-- Bounded encoding
----------------------------------------------------------------------------

-- | Encode 'Text' under the target encoding with a byte-count cap.
-- Codepoint-aware: encodes codepoint by codepoint, stops when adding
-- the next codepoint would exceed the cap. The result is always
-- valid bytes in the target encoding (no split codepoints) and is
-- at most @cap@ bytes long.
--
-- Substitution works as in 'encodeTextLenient': an unrepresentable codepoint becomes a substitute with a 'SubstitutedCodepoint' notice.
-- Truncation, when it happens, surfaces as a 'TruncatedToFitBound' notice carrying the unbounded and written byte counts.
--
-- The caller decides what to do about the notices — slap's create
-- paths typically lift each one to a 'Slap.Status.FieldTruncated'
-- advisory tagged with the format and field name. Padding the encoded
-- bytes to the format's exact field width (with whichever byte that
-- format uses) stays at the call site; this primitive does the
-- encoding and truncation only.
encodeTextBounded :: EncodingName -> Length -> Text -> (ByteString, [LossNotice])
encodeTextBounded encodingName cap text =
  let perCodepoint = map (encodeSingleCodepoint encodingName) (Text.unpack text)
      (taken, remaining) = takeChunksUnderCap cap perCodepoint
      takenBytes         = ByteString.concat (map fst taken)
      substitutionNotes  = mapMaybe snd taken
      truncationNotes    = case remaining of
        [] -> []
        _  -> let writtenBytes  = ByteString.length takenBytes
                  originalBytes = writtenBytes
                                + sum (map (ByteString.length . fst) remaining)
              in [TruncatedToFitBound
                    (OriginalLength  (Length (fromIntegral originalBytes)))
                    (TruncatedLength (Length (fromIntegral writtenBytes)))]
  in (takenBytes, substitutionNotes ++ truncationNotes)

-- | Encode a single codepoint, with the bytes and a substitution notice if the target encoding can't represent it.
-- UTF-8 represents every codepoint, so it never substitutes.
encodeSingleCodepoint
  :: EncodingName -> Char -> (ByteString, Maybe LossNotice)
encodeSingleCodepoint EncodingUtf8 char =
  (TextEncoding.encodeUtf8 (Text.singleton char), Nothing)
encodeSingleCodepoint (EncodingNamed named) char =
  let encoder = useNamedEncoding named
  in if Encoding.encodeable encoder char
       then (Encoding.encodeStrictByteString encoder [char], Nothing)
       else let substitute = chooseSubstitute encoder
                bytes      = Encoding.encodeStrictByteString encoder [substitute]
            in (bytes, Just SubstitutedCodepoint)

-- | Walk a list of per-codepoint encoded chunks, accumulating until
-- the next chunk would push the running byte count past the cap.
-- Returns the prefix that fit and the suffix that didn't, so the
-- caller can compute the truncated byte count and the would-be
-- original count in one walk.
takeChunksUnderCap
  :: Length
  -> [(ByteString, a)]
  -> ([(ByteString, a)], [(ByteString, a)])
takeChunksUnderCap cap = accumulateUnderCap mempty []
  where
    accumulateUnderCap _    takenReversed [] = (reverse takenReversed, [])
    accumulateUnderCap used takenReversed (chunk@(bytes, _) : rest) =
      let nextUsed = used <> byteLength bytes
      in if nextUsed > cap
           then (reverse takenReversed, chunk : rest)
           else accumulateUnderCap nextUsed (chunk : takenReversed) rest

----------------------------------------------------------------------------
-- Fixed-width text fields
----------------------------------------------------------------------------

-- | The meaningful content of a fixed-width text field, read liberally.
-- A fixed field is text followed by padding, and producers spell that
-- padding several ways — trailing spaces, trailing NULs, a NUL
-- terminator then spaces, or the whole field blank.
-- 'readFixedWidthTextField' drops the trailing run of spaces and NULs
-- however it is shaped and reports the contentful part. The one
-- structurally-odd case — real content surviving past a NUL, where the
-- field was meant to have ended — is kept separate so the caller can
-- surface it instead of silently swallowing the bytes.
data FieldContent
  = AllPadding
    -- ^ The field held nothing but padding.
  | Content !EncodedText
    -- ^ Content with a clean end: trailing padding removed, nothing
    -- lurking past a terminator.
  | ContentPastEnd !EncodedText !Length
    -- ^ Content (the part before the first NUL, its own trailing spaces
    -- removed), paired with the 'Length' of the tail that ran on past
    -- that terminator — the anomaly the caller reports, and which a
    -- re-encode drops.
  deriving (Eq, Show)

-- | Read a decoded fixed-width field down to its content. The encoding
-- tag rides through unchanged; only the 'Text' payload is trimmed. See
-- 'FieldContent' for the three shapes a field can take.
readFixedWidthTextField :: EncodedText -> FieldContent
readFixedWidthTextField (EncodedText encoding content) =
  let withoutTrailingPadding = Text.dropWhileEnd isFieldPadding content
  in if Text.null withoutTrailingPadding
       then AllPadding
       else case Text.findIndex (== '\NUL') withoutTrailingPadding of
              Nothing ->
                Content (EncodedText encoding withoutTrailingPadding)
              Just terminatorIndex ->
                let beforeTerminator =
                      Text.dropWhileEnd (== ' ')
                        (Text.take terminatorIndex withoutTrailingPadding)
                    tailPastTerminator =
                      Length (fromIntegral (Text.length withoutTrailingPadding - terminatorIndex))
                in ContentPastEnd
                     (EncodedText encoding beforeTerminator) tailPastTerminator
  where
    isFieldPadding character = character == ' ' || character == '\NUL'

-- | Decode a fixed-width field's raw bytes under the given encoding and
-- read it down to the content to store, bundling the decode-substitution
-- advisories with any content-past-end advisory. This is the single call
-- a format's parse makes per fixed-width text field. A blank field
-- stores empty content under the field's own encoding; content past a
-- NUL terminator stores the part before the terminator and raises
-- 'Slap.Status.FieldContentPastEnd'.
decodeFixedWidthTextField
  :: EncodingName -> FormatLabel -> FieldName -> ByteString
  -> (EncodedText, [SlapAdvisory])
decodeFixedWidthTextField encoding label field bytes =
  let (decoded, decodeNotices) = decodeTextLenient encoding bytes
      decodeAdvisories         = decodeLossAdvisories label field decodeNotices
  in case readFixedWidthTextField decoded of
       AllPadding ->
         (decoded { encodedTextContent = Text.empty }, decodeAdvisories)
       Content content ->
         (content, decodeAdvisories)
       ContentPastEnd content tailPastEnd ->
         ( content
         , decodeAdvisories ++ [FieldContentPastEnd label field tailPastEnd] )

----------------------------------------------------------------------------
-- Advisory adaptation
----------------------------------------------------------------------------

-- | Adapt the substitution notices a 'decodeTextLenient' call emitted into 'SlapAdvisory' values tagged with the format and field.
-- The advisory carries a count — the field had unrepresentable bytes, and how many — so a clean decode yields no advisory.
decodeLossAdvisories
  :: FormatLabel -> FieldName -> [LossNotice] -> [SlapAdvisory]
decodeLossAdvisories label field notices =
  [FieldDecodedSubstituted label field count | count@(SubstitutionCount n) <- [substitutionCount notices], n > 0]

-- | Adapt the loss notices an 'encodeTextLenient' or 'encodeTextBounded'
-- call emitted into 'SlapAdvisory' values tagged with the format and
-- field. Substitution notices fold to a single 'FieldEncodedSubstituted'
-- carrying the count; a 'TruncatedToFitBound' notice (only produced by
-- the bounded path) lifts to 'FieldTruncated' with the same byte
-- counts. Either kind, or both, can fire from one call.
encodeLossAdvisories
  :: FormatLabel -> FieldName -> [LossNotice] -> [SlapAdvisory]
encodeLossAdvisories label field notices =
  let substitutions = length [() | SubstitutedCodepoint <- notices]
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

-- | Resolve a user-supplied encoding name into a 'NamedEncoding', or refuse with the name that didn't resolve.
-- The resolution engine ('resolveEncoderByName') tries the name as given,
-- a few case- and separator-normalization variants, and the curated 'documentedLocaleAliases' table;
-- the first that the @encoding@ library recognizes wins.
resolveEncodingName :: Text -> Either UnresolvableEncodingName NamedEncoding
resolveEncodingName name = case resolveEncoderByName (Text.unpack name) of
  Just encoder -> Right (NamedEncoding name encoder)
  Nothing      -> Left (UnresolvableEncodingName name)

-- | Try the @encoding@ library's lookup against the given encoding
-- name and a small set of normalization variants. The first variant
-- that resolves wins; if all fail, returns 'Nothing'. Variants
-- handle case differences, dash\/underscore variations, and the
-- common Windows codepage names spelled as @CPnnnn@.
resolveEncoderByName :: String -> Maybe DynEncoding
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

-- | Curated alias table: the locale-style names a user might supply (what a Windows host or non-UTF-8 Unix locale spells),
-- mapped to a list of names to try against the @encoding@ library.
-- Three categories of entry:
--
--   * /Direct/ — the @encoding@ library ships an encoder under the mapped name.
--     The Windows codepage family, the DOS\/OEM codepages, Cyrillic KOI8-R\/U,
--     the Japanese standards (Shift-JIS, ISO-2022-JP), and the Chinese GB18030 standard are in this category.
--     Uses the library's own name, so the decode goes through the @encoding@ library's table for that codepage rather than a near-miss substitute.
--
--   * /Compatible superset/ — the @encoding@ library doesn't ship the exact codepage but does ship a strictly compatible superset.
--     The library doesn't ship CP936 (Simplified Chinese), so it maps to GB18030, the standardized successor that extends GBK and GB2312.
--     Microsoft's CP1250-1257 fall back to the matching ISO-8859 variant where the codepage entry isn't recognized;
--     the ISO cousins are ASCII-clean and differ only in upper-half glyphs
--     (e.g. CP1252's @\\x80@ Euro sign vs ISO-8859-1's @\\x80@ control character).
--
--   * /Documented gap/ — the @encoding@ library doesn't ship an encoder and there's no compatible superset in the library.
--     The entry has an empty list, so the lookup fails and 'resolveEncodingName' returns 'Left' rather than mojibake from a near-miss decoder.
--     Listed by name so a future-self reading the code sees the encoding was considered and the cost of closing it.
--     Korean Wansung (CP949), Big5 (CP950 and the bare-name variants), the EUC-* family, TIS-620 (Thai),
--     VISCII and TCVN (Vietnamese), ARMSCII-8 (Armenian), and TSCII (Tamil) all sit here.
--     Closing any of them needs either a backend swap (@text-icu@ against ICU4C covers all of these) or a hand-rolled decoder.
--
-- Mappings follow Microsoft codepage conventions and IANA charset names,
-- and have not been exercised under each target locale on a real host: the documented-but-untested caveat.
-- The upper-half MS-vs-ISO drift noted under /Compatible superset/ is the failure mode to watch;
-- ASCII and text whose upper-half characters are well-defined in the cousin round-trip.
--
-- The table is keyed on the @uppercase + dashes-and-underscores-stripped@ form of the locale name,
-- so @cp1252@, @CP-1252@, @CP_1252@, @Shift_JIS@, @shift-jis@, and @SHIFTJIS@ all reach the same arm.
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

  -- Documented gaps (see the header): no encoder, no compatible superset, so an empty list;
  -- the lookup fails and 'resolveEncodingName' returns 'Left'.
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
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically AdvertisedEncodingFamily

-- | Every text encoding slap decodes, one canonical name per encoder, grouped for a legible @--encodings@ listing.
-- This is the full set the bundled @encoding@ library provides as field encodings:
-- a name missing here is one slap can't decode.
-- slap additionally /accepts/ alternate spellings of these (case- and separator-insensitive, plus the 'documentedLocaleAliases' locale names).
-- The library's non-field internals — raw JIS X 0201\/0208\/0212, bare ISO-2022, and punycode — are deliberately omitted;
-- they aren't sensible encodings to tag a metadata text field as.
advertisedEncodings :: [AdvertisedEncodingFamily]
advertisedEncodings =
  [ AdvertisedEncodingFamily "Unicode"   ["utf-8", "utf-16", "utf-32"]
  , AdvertisedEncodingFamily "ISO 8859"  ["iso-8859-1", "iso-8859-2", "iso-8859-3", "iso-8859-4", "iso-8859-5",
                                          "iso-8859-6", "iso-8859-7", "iso-8859-8", "iso-8859-9", "iso-8859-10",
                                          "iso-8859-11", "iso-8859-13", "iso-8859-14", "iso-8859-15", "iso-8859-16"]
  , AdvertisedEncodingFamily "Windows"   ["cp1250", "cp1251", "cp1252", "cp1253", "cp1254", "cp1255", "cp1256", "cp1257", "cp1258"]
  , AdvertisedEncodingFamily "DOS / OEM" ["cp437", "cp737", "cp775", "cp850", "cp852", "cp855", "cp857", "cp860",
                                          "cp861", "cp862", "cp863", "cp864", "cp865", "cp866", "cp869", "cp874"]
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
