{-# LANGUAGE StrictData #-}

module Slap.Error
  ( SlapError(..)
  , SlapWarning(..)
  , ApplyError(..)
  , CursorKind(..)
  , UnencodeabilityReason(..)
  , DecompressionFailure(..)
  , BSDiffSection(..)
  , DecompressionCause(..)
  , CompressionAlgorithm(..)
  , decompressionAlgorithm
  , compressionAlgorithmName
  , bsDiffSectionName
  , renderDecompressionFailure
  , DroppedValue(..)
  , CreateResult(..)
  , Parsed(..)
  , Outcome(..)
  , noWarnings
  , OverlapCount(..)
  , ClippedRecordCount(..)
  , OOBBlockCount(..)
  , MarkerOvershootBytes(..)
  , OOBOvershootBytes(..)
  , VerificationSide(..)
  , HashAlgorithm(..)
  , ExpectedAdler32(..)
  , ActualAdler32(..)
  , ByteCheckLabel(..)
  , verificationSideLabel
  , hashAlgorithmLabel
  , renderSlapError
  , renderApplyError
  , renderCursorKind
  , renderSlapWarning
  ) where

import Numeric (showHex)
import Slap.FileContents (PatchFileContents)
import Slap.FormatLabel (FormatLabel(..), formatLabelName)
import Slap.Checksum (CRC32, Adler32, MD5Hash(..), SHA1Hash(..),
                      showCRC32, showAdler32,
                      ExpectedCRC32(..), ActualCRC32(..))
import Slap.Display.Primitives (hexByteString, padHex, renderPrintableASCIIOrHex)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), ActionIndex(unActionIndex),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ActualSize(..), ExpectedSize(..),
                     MaxAddressableSize(..),
                     DeclaredTargetSize(..), NaturalTargetSize(..),
                     RequiredLength(..), ActualLength(..),
                     EncodedLength(..), MaxLength(..),
                     OriginalLength(..), TruncatedLength(..),
                     ActualOffset(..), MaxOffset(..),
                     SentinelOffset(..),
                     ExpectedMagic(..), ActualMagic(..),
                     TrailerMarker(..),
                     ParsedSizeValue(..), FoundVersion(..),
                     RawFlagByte(..), EncodingMethodByte(..))
import Slap.Narrow (NarrowingFailure(..))
import Slap.FieldName (FieldName(..), fieldNameLabel)
import Slap.Constraint (Constraint(..), constraintFlagName, constraintName)
import Slap.Dialect (Dialect, dialectFlagName, dialectName)
import Slap.MetadataField (MetadataField, metadataFieldFlagName, metadataFieldName)
import Slap.PatchField (PatchField, fieldName)
import Slap.XDelta1.Types (XDelta1SourceShape(..))

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Word (Word8)

----------------------------------------------------------------------------
-- DroppedValue
----------------------------------------------------------------------------

data DroppedValue
  = DroppedCRC CRC32
  | DroppedMD5 MD5Hash
  | DroppedSHA1 SHA1Hash
  | DroppedDescription String
  | DroppedSize FileSize
  | DroppedEmpty
  deriving (Show, Eq)

renderDroppedValue :: DroppedValue -> String
renderDroppedValue (DroppedCRC crc)             = "0x" ++ showCRC32 crc
renderDroppedValue (DroppedMD5 hash)            = hexByteString (unMD5Hash hash)
renderDroppedValue (DroppedSHA1 hash)           = hexByteString (unSHA1Hash hash)
renderDroppedValue (DroppedDescription text)    = "\"" ++ text ++ "\""
renderDroppedValue (DroppedSize size)           = show (unFileSize size) ++ " bytes"
renderDroppedValue DroppedEmpty                 = ""

----------------------------------------------------------------------------
-- CursorKind
----------------------------------------------------------------------------

-- | Which of BPS's relative cursors misbehaved. BPS tracks two
-- independent relative cursors — 'SourceCursor' points into the
-- source ByteString for 'SourceCopy' actions, 'TargetCursor' points
-- into the output buffer for 'TargetCopy' actions. Apply errors
-- related to cursor underflow carry this tag to disambiguate.
data CursorKind = SourceCursor | TargetCursor
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- UnencodeabilityReason
----------------------------------------------------------------------------

-- | Why a (source, target) pair cannot be encoded as a UPS patch.
-- Per the UPS spec, each diff run must end with a terminator byte
-- that counts against the target file pointer; this makes certain
-- byte configurations impossible to represent.
data UnencodeabilityReason
  = UPSLastByteDiffers     -- ^ target's final byte differs from source (with
                           --   virtual zero-padding past source end), so any
                           --   diff run at that position would need a terminator
                           --   past target end
  | UPSSourceTailNonZero   -- ^ source has non-zero bytes past target size,
                           --   which appear as diffs against virtual-zero
                           --   target and cannot be represented without
                           --   writing past target end
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- ApplyError
----------------------------------------------------------------------------

-- | Format-agnostic errors encountered during patch application.
-- Paired with a 'FormatLabel' at the outer boundary via the
-- 'ApplyFailed' 'SlapError' constructor. Most variants carry an
-- 'ActionIndex' identifying which action in the patch's action
-- stream triggered the error — this is the first thing to look at
-- when debugging a malformed patch.
--
-- Where a variant would otherwise have two positional arguments of
-- the same base type (two 'Offset's, two 'Length's, two 'FileSize's),
-- the arguments are typed with role newtypes from 'Slap.Measure'
-- ('ReadOffset' vs 'WritePosition', 'RequestedLength' vs
-- 'RemainingLength', 'ActualSize' vs 'ExpectedSize') so the field
-- roles are visible at construction, pattern-match, and rendering
-- sites without needing to consult documentation.
data ApplyError

  -- | A relative cursor (source or target) went negative after
  -- applying the action's delta. Arguments are all distinct types,
  -- so no role newtypes needed.
  = ApplyCursorUnderflow CursorKind ActionIndex SignedOffset

  -- | An action would read past the end of the source ByteString.
  -- The 'Offset' is the would-be read end; the 'FileSize' is the
  -- actual source size. Arguments are distinct types, so no role
  -- newtypes needed.
  | ApplySourceReadOutOfBounds ActionIndex Offset FileSize

  -- | A TargetCopy referenced an output position at or past the
  -- current write position (i.e., unwritten memory).
  | ApplyTargetReadUnwritten ActionIndex ReadOffset WritePosition

  -- | An action's output length would exceed the remaining space in
  -- the target buffer.
  | ApplyWritesPastTarget ActionIndex RequestedLength RemainingLength

  -- | The action stream was exhausted but the target buffer is not
  -- fully written. No 'ActionIndex' because this error fires after
  -- the stream ends and no specific action is responsible — the
  -- whole patch is short. (There is no corresponding
  -- @ApplyTargetOverfilled@ because 'ApplyWritesPastTarget' catches
  -- over-writes per-action before they can happen; writing past
  -- target is impossible if every action's length is validated
  -- against remaining space before the copy runs.)
  | ApplyTargetUnderfilled WritePosition ExpectedSize

  -- | A record's offset is negative. Only possible for formats that
  -- store signed offsets (PPF3 uses signed 64-bit). The Offset is
  -- the negative value as parsed.
  | ApplyNegativeRecordOffset ActionIndex Offset

  -- | A PPF4 Replace record would write past the source file's end.
  -- PPF4 Replace records cannot grow the file (only Append records
  -- can); the reference applier rejects this with ERROR_BAD_SIZE.
  -- The 'Offset' is the record's start; the 'RequestedLength' is the
  -- record's payload length; the 'FileSize' is the source size.
  | ApplyReplaceGrowsFile ActionIndex Offset RequestedLength FileSize

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- DecompressionFailure
----------------------------------------------------------------------------

-- | A decompression failure, modeled in the 'ApplyError' style — its
-- own narrower vocabulary, lifted into 'SlapError' via a single
-- constructor.  One constructor per real decompression site slap
-- knows about; each carries only the axes that actually vary at that
-- site.  Adding xdelta3 / VCDIFF secondary compression adds a
-- constructor here parameterized over 'CompressionAlgorithm'.
data DecompressionFailure
  = Yay0WrapperFailed                       DecompressionCause
  | NINJA1Failed                            DecompressionCause
  | XDelta1Failed                           DecompressionCause
  | BSDiffSectionFailed   BSDiffSection     DecompressionCause
  -- When VCDIFF secondary compression is supported (today's parser
  -- rejects it at 'VCDIFF/Parse.hs:113'), add:
  -- | VCDIFFSectionFailed VCDIFFSection CompressionAlgorithm DecompressionCause
  deriving (Show, Eq)

-- | BSDiff's three bzip2-compressed sections.
data BSDiffSection = BSDiffControl | BSDiffDiff | BSDiffExtra
  deriving (Show, Eq)

-- | The decompressor's diagnostic message.  Carried verbatim from
-- flate2 / bzip2-rs / slap's own Yay0 implementation; slap relays
-- the underlying library's 'Display' rather than re-classifying.
-- Across the FFI seam, the bytes are decoded as UTF-8 (see
-- 'Slap.Compression.Stream.readRustString'), so the 'String' here
-- carries real Unicode code points, not latin1 byte-Chars.
newtype DecompressionCause = DecompressionCause { unDecompressionCause :: String }
  deriving (Show, Eq)

-- | The compression algorithms slap knows about.  Closed and
-- complete: the four currently in use plus the three the VCDIFF
-- spec at @docs/rfc-vcdiff/spec.md:108-110@ already names (DJW,
-- LZMA, FGK).  Today no consumer dispatches on this — both the
-- renderer and the algorithm-of-failure projection are scaffolding
-- for the xdelta3 work, where 'VCDIFFSectionFailed' will carry it
-- as a parameter and 'compressionAlgorithmName' will render it.
data CompressionAlgorithm
  = Zlib | Gzip | Bzip2 | Yay0
  | DJW  | LZMA | FGK
  deriving (Show, Eq, Ord, Enum, Bounded)

----------------------------------------------------------------------------
-- SlapError
----------------------------------------------------------------------------

data SlapError

  -- Detection
  = UnrecognizedFormat
  | AmbiguousDetection [FormatLabel]

  -- Parse: structural
  | InputTooShort FormatLabel RequiredLength ActualLength
  | BadMagic FormatLabel ActualMagic
  | BadVersion FormatLabel FoundVersion
  | UnsupportedSubformat FormatLabel String
  | TruncatedRecord FormatLabel Int Length Length
  | NegativeSize FormatLabel FieldName ParsedSizeValue
  | DecompressionFailed DecompressionFailure

  -- | A parsed record's effective end position lies beyond the
  -- variant's wire-format spec ceiling. The 'ActionIndex' names the
  -- offending record's position in the wire stream; the
  -- 'ActualOffset' is the record's computed end position
  -- (@offset + payloadLength@); the 'MaxOffset' is the variant's
  -- maximum addressable end (typically @maxAddressableOffset +
  -- maxRecordPayload@). Used by IPS-family parsers to reject
  -- records that name a position the format cannot represent on
  -- the wire, before they can flow through to the apply layer.
  | RecordExceedsAddressableRange FormatLabel ActionIndex ActualOffset MaxOffset

  -- | A parsed record carries a structurally malformed field — for
  -- example an RLE record whose run length is zero, or any other
  -- per-record value the spec or slap's strict discipline rejects
  -- as invalid. The 'ActionIndex' names the offending record; the
  -- 'FieldName' identifies which field of that record was
  -- malformed. Distinct from 'TruncatedRecord' (record was too
  -- short) and 'NegativeSize' (a top-level header size was
  -- negative).
  | MalformedRecordField FormatLabel ActionIndex FieldName

  -- | A parser found bytes after a recognized stream-closing trailer
  -- marker that don't match any post-trailer shape the format
  -- accepts. The motivating example is the IPS family: 'StandardIPS'
  -- accepts an empty post-@"EOF"@ trailer, a 3-byte post-EOF truncation
  -- marker, or an EBP JSON metadata blob, while 'IPS32' accepts only
  -- the empty post-@"EEOF"@ trailer; bytes outside those shapes are
  -- a structured parse failure rather than a 'Get'-monad
  -- passthrough. The 'TrailerMarker' carries the marker bytes the
  -- parser was anchored to so the renderer can name them ("after
  -- EOF marker", "after EEOF marker") without knowing about
  -- format-specific variants. The 'ActualLength' is the byte count
  -- of the unrecognized trailer slice.
  | UnrecognizedTrailer FormatLabel TrailerMarker ActualLength

  -- Parse: integrity
  | PatchCRCMismatch FormatLabel ExpectedCRC32 ActualCRC32
  | TrailingMagicMismatch FormatLabel ExpectedMagic ActualMagic

  -- Parse: content
  | UnknownFlag FormatLabel FieldName RawFlagByte
  | UnsupportedEncodingMethod FormatLabel EncodingMethodByte

  -- | A NINJA2 patch's PATCH_ENC byte (offset 6 of the fixed header)
  -- is not 0 (system) or 1 (UTF-8). The NINJA2 spec defines no other
  -- values; slap refuses rather than fabricate a fallback encoding,
  -- because PATCH_ENC governs how every text field in the patch is
  -- decoded and slap has no honest answer for an undefined value.
  | NINJA2UnrecognizedPatchEncoding !Word8

  | MalformedTextField FormatLabel String
  | EntryOutsideBlock FormatLabel String

  -- Parse: generic Get monad failures
  | ParseError FormatLabel String

  -- | The xdelta1 parser rejected a source-list shape outside the
  -- four spec-permitted configurations (@[]@, @[data]@, @[file]@,
  -- @[data, file]@). The 'String' carries a human-readable
  -- description of what was found ("3 sources", "[file, data]",
  -- "[file, file]", etc.) for diagnostic clarity. The wire encodes
  -- the source list as an EDSIO length-prefixed sequence, so any
  -- count parses structurally; both author-produced authorities —
  -- the canonical tool ('xdmain.c:1741-1768',
  -- 'EC_XdIncompatibleDelta') and the xdelta.1 manpage
  -- (MacDonald 2001) — agree on at-most-one-file-source.
  | UnsupportedXDelta1Shape String

  -- | An xdelta1 instruction referenced a source index that does
  -- not exist in the patch's declared 'XDelta1SourceShape'. Caught
  -- at parse time so an off-spec apply can never fire. The 'Int64'
  -- carries the offending index as it appeared on the wire; the
  -- 'XDelta1SourceShape' is the patch's parsed shape, included so
  -- the renderer can name both the bad index and the (small) set of
  -- indices that would have been valid.
  | XDelta1InstructionIndexOutOfRange Int64 XDelta1SourceShape

  -- Apply
  | NegativeTargetSize FormatLabel FileSize
  | ApplyFailed FormatLabel ApplyError

  -- Undo
  | UndoFailed FormatLabel ApplyError

  -- Create / Encode
  | CannotExpressTargetShrinkage FormatLabel ActualSize ExpectedSize
  | UPSUnencodeablePair FormatLabel UnencodeabilityReason
  | NarrowingError !NarrowingFailure

  -- | A create-path input (source or target) is larger than the
  -- host platform's addressable range. slap's varint encoders
  -- shuttle lengths through 'Int', so on a 32-bit platform where
  -- 'Int' is 31-bit-addressable, a file over ~2 GB would truncate
  -- via 'fromIntegral' and produce a malformed patch. The
  -- 'ActualSize' is the offending file's size; the
  -- 'MaxAddressableSize' is the host's 'maxBound :: Int'. On 64-bit
  -- platforms the cap is ~9 EB and this error is effectively dead.
  | FileExceedsAddressableRange FormatLabel ActualSize MaxAddressableSize

  -- | A record's offset lands on the format's trailer sentinel and
  -- the encoder has no way to shift it back: either the source bytes
  -- needed for the shift-and-prepend fix are absent (source-less
  -- conversion), the source is shorter than the preceding-byte index,
  -- or the sentinel sits at offset @0@ so there is no preceding byte
  -- to consume. IPS and IPS32 are the only affected formats today;
  -- see 'Slap.IPS.Create.resolveSentinelCollisions' for the fix path
  -- that this error is the failure mode of.
  | SentinelCollisionUnfixable FormatLabel SentinelOffset

  -- | The PPF2 wire format mandates a 1024-byte block sampled from
  -- source offset 0x9320, so any source file shorter than 0x9720
  -- (= 0x9320 + 0x400) bytes can't supply one. The reference DOS
  -- @MakePPF.exe@ crashes with a Borland Pascal "runtime error 205"
  -- (FP overflow) on undersized inputs; slap refuses with this
  -- structured error instead. The 'ActualSize' is the source's size,
  -- the 'ExpectedSize' is the @0x9720@-byte minimum.
  | SourceTooSmallForPPF2Validation FormatLabel ActualSize ExpectedSize

  | FieldTooLong FormatLabel FieldName EncodedLength MaxLength
  | EncodingFailure FormatLabel FieldName String

  -- Convert
  | MissingRequiredField FormatLabel PatchField

  -- | A refusal by the contract layer when the source patch carries
  -- one or more 'PatchField' values that affect the output bytes of
  -- the apply operation (see 'Slap.PatchField.affectsApplyOutput')
  -- and that the target format has no wire representation for.
  -- Silently dropping the fields would change what the resulting
  -- patch produces on apply, so the conversion is refused outright
  -- rather than papered over with a warning. The 'FormatLabel' names
  -- the target format being refused; the inner list pairs each
  -- offending field with the target formats that do preserve it
  -- (possibly empty), so the renderer can point the user at a
  -- target that would work. Only 'FieldTruncation' reaches this error
  -- today; the list shape exists so future apply-output-affecting
  -- fields drop into the same refusal path without new plumbing.
  | ApplyOutputFieldsWouldBeDropped FormatLabel [(PatchField, [FormatLabel])]

  | DiffRequiresSource FormatLabel

  -- | The user set one or more metadata fields via CLI flags that
  -- the target format doesn't consume.  Surfaced before any IO so
  -- the user learns what went wrong before their files are touched.
  -- The 'NonEmpty MetadataField' names every concept the user
  -- expressed; the 'FormatLabel' names the target format that would
  -- silently drop them. Rendering enumerates each offending CLI flag
  -- and the target, so the message points the user at every thing
  -- to fix in one read.
  | MetadataFieldRejected (NonEmpty MetadataField) FormatLabel

  -- | The user opted into one or more 'Constraint's the target
  -- format cannot honor. Same shape and rationale as
  -- 'MetadataFieldRejected'.
  | ConstraintNotSupported (NonEmpty Constraint) FormatLabel

  -- | The user toggled one or more dialect axes via CLI flags that
  -- the target (or, for convert, neither side of the chain) admits.
  -- Surfaced by 'Slap.Convert.rejectIncompatibleDialects' before any
  -- parsing or encoding work begins.
  | DialectNotSupported (NonEmpty Dialect) FormatLabel

  -- | The IPS create gate refused a truncation marker whose declared
  -- target size doesn't satisfy SNESTool's
  -- @(size & 0xFFF) == 0x200@ shape filter. Surfaced by
  -- 'Slap.Convert.rejectNonSMCShapedTruncation'; only fires when the
  -- user opted into 'Slap.IPS.Types.RequireSMCShapedTruncation'.
  | TruncationViolatesSMCShape !FileSize

  -- | A verification check would have produced a 'SlapWarning' but
  -- the user did not pass @--no-verify@, so the mismatch is fatal.
  -- The embedded 'SlapWarning' is one of the four "downgraded fatal"
  -- kinds: 'VerificationCRCMismatch', 'VerificationHashMismatch',
  -- 'VerificationAdler32Mismatch', or 'VerificationFileSizeMismatch'.
  -- The renderer delegates to 'renderSlapWarning' for the body and
  -- appends the @--no-verify@ tail. No type-level guarantee enforces
  -- that the embedded warning is one of the four fatal-promotable
  -- kinds; the four 'check*' helpers in 'Main' are the only callers
  -- and the audit surface is tractable.
  | VerificationFatal SlapWarning

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- SlapWarning
----------------------------------------------------------------------------

data SlapWarning

  -- Patch quality
  = EmptyPatch FormatLabel String
  | NoEOFMarker FormatLabel

  -- | An IPS-family RLE record whose run-length field was zero was
  -- accepted verbatim as a no-op. The spec does not speak to the
  -- case, and slap's live encoder never emits it; the warning
  -- signals a parsed oddity so the user can decide whether the
  -- source patch is trustworthy. The 'ActionIndex' names the
  -- offending record's position in the wire record stream.
  | ZeroCountRLERecord FormatLabel ActionIndex

  -- | A BPS patch carries the non-canonical @0x81@ encoding of zero
  -- in a 'SourceCopy' or 'TargetCopy' signed-delta varint. Both
  -- @0x80@ and @0x81@ decode to a delta of zero — the sign-magnitude
  -- scheme treats @0x81@ as "negative zero" — but only @0x80@ is the
  -- canonical form, and slap's encoder never emits @0x81@. The
  -- warning fires once per patch (no payload) and signals either a
  -- non-canonical producer or transit corruption; the parse itself
  -- proceeds normally. See @docs/bps/questions.md@ → "two encodings
  -- for zero-delta".
  | NegativeZeroInBPS

  -- | At least one pair of records in an IPS-family patch writes
  -- to overlapping regions of the target. Overlap is permitted and
  -- well-defined (later writes clobber earlier ones), but it's
  -- unusual enough that slap flags it. The 'OverlapCount' carries
  -- the total number of intersecting pairs found during the parse;
  -- the warning is only emitted when that count is at least one.
  -- Per-pair detail is intentionally omitted: a pathological
  -- mutually-overlapping cluster of @k@ records would otherwise
  -- produce @k*(k-1)/2@ near-identical warning lines that drown
  -- everything else, and the reader's question is "does this patch
  -- have overlapping writes" not "exactly which pairs".
  | OverlappingRecords FormatLabel OverlapCount

  -- | An IPS-family record carries a smaller offset than the
  -- record that preceded it in the wire stream. slap applies
  -- records strictly in wire order, so unsorted records still
  -- produce correct output, but well-formed patches are sorted by
  -- offset; an unsorted stream is worth flagging. Only the first
  -- out-of-order pair is reported per parse — one warning is enough
  -- to tell the reader the stream is unsorted. The 'ActionIndex'
  -- names the later-in-wire-order record whose offset is lower than
  -- the record before it.
  | UnsortedRecords FormatLabel ActionIndex

  -- | An 'IPS32' patch had trailing bytes past the @"EEOF"@ marker
  -- that did not match any recognized post-trailer shape. slap drops
  -- the trailing slice and proceeds. 'StandardIPS' has three
  -- well-attested post-@"EOF"@ shapes (empty, 3-byte post-EOF
  -- truncation marker, EBP JSON blob) and keeps its strict rejection of
  -- garbage trailers; 'IPS32' has none, and a lenient drop is the
  -- useful choice in the absence of a shape to recognize. The
  -- 'Length' is the byte count dropped.
  | IPS32TrailingBytes FormatLabel Length

  -- | A 'StandardIPS' patch's post-EOF truncation marker declared a
  -- target size smaller than the natural size, and slap honored it.
  -- Surfaces the truncation as a deliberate diagnostic even when no
  -- records cross the boundary. Pairs with 'IPSRecordsClippedByMarker'
  -- when records were also clipped.
  | IPSTruncationMarkerHonored FormatLabel DeclaredTargetSize NaturalTargetSize

  -- | One or more records' write regions extended past the
  -- truncation boundary that slap honored, and were clipped to fit.
  -- Aggregate count in the style of 'OverlappingRecords'; per-record
  -- detail omitted to keep a pathological patch from drowning
  -- everything else. Only fires when at least one record crossed the
  -- boundary; the 'ActionIndex' names the first such record in wire
  -- order.
  | IPSRecordsClippedByMarker FormatLabel ClippedRecordCount ActionIndex MarkerOvershootBytes

  -- | A 'StandardIPS' patch's truncation marker declared a target
  -- size larger than the natural size, which would grow the output
  -- via zero-fill. Per the docs/ips/questions.md policy, slap ignores
  -- the marker for sizing and emits this warning so the user learns
  -- the patch declared something slap chose not to act on.
  | IPSTruncationMarkerIgnored FormatLabel DeclaredTargetSize NaturalTargetSize

  -- | An APS-N64 type-1 patch declares a country code byte that is
  -- not one of the documented N64 cartridge ROM region codes. The
  -- byte is preserved verbatim for round-tripping; slap proceeds
  -- normally because the country byte is informational and gates no
  -- decoding decision. The 'Word8' is the unrecognized byte.
  | APSN64UnrecognizedCountry !Word8

  -- Conversion: dropped fields
  | FieldDropped PatchField DroppedValue
  | UndoDataDropped Int
  | ValidationBlockDropped
  | DisabledEntriesDropped Int
  | BlockDescriptionsDropped
  | MetadataDropped Int

  -- Conversion: defaults assumed
  | DefaultRomType FormatLabel
  | DefaultImageType FormatLabel
  | IncludingUndoByDefault
  | IncludingValidationByDefault
  | SourceHashesMissing FormatLabel

  -- Encoding
  | FieldTruncated FormatLabel FieldName OriginalLength TruncatedLength
  | EncodingGap FormatLabel FormatLabel

  -- Platform conversion
  | PlatformNotAvailable FormatLabel String  -- target format, platform name
  | PlatformAmbiguous FormatLabel String String String  -- source format, combined name, default name, override value

  -- Apply: out-of-bounds block clipping
  | ApplyOOBBlocksSkipped FormatLabel OOBBlockCount ActionIndex OOBOvershootBytes FileSize

  -- Format-specific
  | SubformatConverted FormatLabel String String
  | OffsetShiftApplied

  -- Verification: source/target integrity check mismatches
  --
  -- These fire from app/Main.hs's verification helpers. The four
  -- "downgraded fatal" kinds (CRC, hash, Adler32, file-size) emit
  -- as warnings when the user passed --no-verify; the same mismatch
  -- promotes to 'VerificationFatal' under EnforceVerification. The
  -- four "advisory" kinds always emit as warnings under either
  -- policy; they have no fatal counterpart because the underlying
  -- check is advisory by design (block CRC16, PPF validation block,
  -- file-size advisory, source-bytes byte-range comparison), and
  -- --no-verify does not silence them — the flag's contract is the
  -- fatal-vs-warning axis for fatal-class checks only.
  | VerificationCRCMismatch       VerificationSide ExpectedCRC32 ActualCRC32
  | VerificationHashMismatch      VerificationSide HashAlgorithm
  | VerificationAdler32Mismatch   Offset ExpectedAdler32 ActualAdler32
  | VerificationFileSizeMismatch  VerificationSide ExpectedSize ActualSize
  | VerificationBlockCRC16Mismatch VerificationSide Offset
  | VerificationPPFBlockMismatch  Offset
  | VerificationFileSizeAdvisory  ExpectedSize ActualSize
  | VerificationSourceBytesMismatch ByteCheckLabel Offset

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- CreateResult
----------------------------------------------------------------------------

data CreateResult = CreateResult
  { resultBytes    :: !PatchFileContents
  , resultWarnings :: ![SlapWarning]
  } deriving (Show)

----------------------------------------------------------------------------
-- Parsed
----------------------------------------------------------------------------

-- | The parse-side companion to 'CreateResult': a successfully
-- parsed payload paired with any warnings the parser accumulated.
-- Two fields: the parsed value (parametric) and the warning list.
data Parsed value = Parsed !value ![SlapWarning]
  deriving (Show)

----------------------------------------------------------------------------
-- Outcome
----------------------------------------------------------------------------

-- | The value and warning channels of an apply or undo operation.
-- Mirrors 'CreateResult' on the create side and 'Parsed' on the parse
-- side — every value-producing operation in slap pairs its value with
-- a warning channel. The polymorphic parameter lets a single envelope
-- serve both apply (carrying 'OutputFileContents') and undo (carrying
-- 'InputFileContents') without duplicating the shape; the 'Functor'
-- instance lets a wrapper function the inner value through 'fmap'
-- without unpacking the envelope.
--
-- Wrap sites that don't emit warnings use 'noWarnings' to lift their
-- bare value into the envelope; sites that do construct 'Outcome'
-- directly with the warning list.
data Outcome a = Outcome
  { outcomeValue    :: !a
  , outcomeWarnings :: ![SlapWarning]
  }
  deriving (Show, Functor)

-- | Wrap a warning-free value in the 'Outcome' envelope. Every wrap
-- site at the apply/undo boundary uses this so the @[]@ warning list
-- has exactly one home; specific apply or undo paths that actually
-- emit warnings will construct 'Outcome' directly.
noWarnings :: a -> Outcome a
noWarnings value = Outcome value []

----------------------------------------------------------------------------
-- OverlapCount — payload of the OverlappingRecords warning
----------------------------------------------------------------------------

-- | The number of overlapping record pairs detected during an
-- IPS-family parse. Carried by the 'OverlappingRecords' warning so
-- the reader sees both that the patch contains overlapping writes
-- and how many such intersections were found, without enumerating
-- every pair (a pathological mutually-overlapping cluster of @k@
-- records would otherwise produce @k*(k-1)/2@ near-duplicate
-- warning lines). A value of zero is structurally impossible: the
-- warning is only emitted when at least one pair was found.
newtype OverlapCount = OverlapCount { unOverlapCount :: Int }
  deriving (Eq, Ord, Show)

-- | The number of IPS records clipped to fit a honored truncation
-- marker. Value-zero is structurally impossible: the warning is
-- only emitted when at least one record crossed the boundary.
newtype ClippedRecordCount = ClippedRecordCount { unClippedRecordCount :: Int }
  deriving (Eq, Ord, Show)

-- | The number of UPS blocks whose write region extends past the
-- declared target file size. Value-zero is structurally impossible:
-- the warning is only emitted when at least one block was OOB.
-- Peer to 'ClippedRecordCount' — both count records-or-blocks that
-- a format's apply path skipped under a defined policy.
newtype OOBBlockCount = OOBBlockCount { unOOBBlockCount :: Int }
  deriving (Eq, Ord, Show)

-- | The total byte length lost across all records clipped by an
-- honored IPS truncation marker. Sums the per-record overshoots
-- (each record's "bytes beyond effective target"), so a single
-- record clipped by 100 bytes and ten records each clipped by 10
-- both report 100. Carried by 'IPSRecordsClippedByMarker' so the
-- user sees not just "records were clipped" but "this much was
-- thrown away." Peer to 'OOBOvershootBytes' — both sum per-event
-- overshoots under a format-specific apply-time policy.
--
-- 'Semigroup' and 'Monoid' are derived through to 'Length' so walk
-- sites accumulating overshoots can use '<>' and 'mempty' directly.
newtype MarkerOvershootBytes = MarkerOvershootBytes { unMarkerOvershootBytes :: Length }
  deriving (Eq, Ord, Show, Semigroup, Monoid)

-- | The total byte length lost across all UPS blocks whose write
-- region extended past the declared target file size. Sums the
-- per-block overshoots, so a single block clipped by 100 bytes and
-- ten blocks each clipped by 10 both report 100. Carried by
-- 'ApplyOOBBlocksSkipped'. Peer to 'MarkerOvershootBytes'.
--
-- 'Semigroup' and 'Monoid' are derived through to 'Length' so the
-- 'detectOOBBlocks' walk can use '<>' and 'mempty' directly.
newtype OOBOvershootBytes = OOBOvershootBytes { unOOBOvershootBytes :: Length }
  deriving (Eq, Ord, Show, Semigroup, Monoid)

----------------------------------------------------------------------------
-- Verification: shared payload types
----------------------------------------------------------------------------

-- | Which side of the apply (input ROM or output ROM) a verification
-- check fired against. Carried by the verification 'SlapWarning'
-- constructors so the renderer can name \"input\" vs \"output\" without
-- callers passing strings. The constructor names retain slap's older
-- source\/target vocabulary; the rendered labels track the CLI's
-- input\/output vocabulary.
data VerificationSide = SourceSide | TargetSide
  deriving (Show, Eq)

verificationSideLabel :: VerificationSide -> String
verificationSideLabel SourceSide = "input"
verificationSideLabel TargetSide = "output"

-- | Which hash algorithm a verification check used. Carried by
-- 'VerificationHashMismatch' so the renderer can name "MD5" vs "SHA1"
-- without callers passing strings.
data HashAlgorithm = MD5 | SHA1
  deriving (Show, Eq)

hashAlgorithmLabel :: HashAlgorithm -> String
hashAlgorithmLabel MD5  = "MD5"
hashAlgorithmLabel SHA1 = "SHA1"

-- | An Adler32 value that a patch declared or stored. Peer to
-- 'ExpectedCRC32'; carried by 'VerificationAdler32Mismatch'.
newtype ExpectedAdler32 = ExpectedAdler32 { unExpectedAdler32 :: Adler32 }
  deriving (Show, Eq)

-- | An Adler32 value that was computed from the actual data. Peer to
-- 'ActualCRC32'; carried by 'VerificationAdler32Mismatch'.
newtype ActualAdler32 = ActualAdler32 { unActualAdler32 :: Adler32 }
  deriving (Show, Eq)

-- | The label of an advisory byte-range check ("N64 cart ID",
-- "N64 country", "N64 CRC", \[future\] ...). Carried by
-- 'VerificationSourceBytesMismatch' so the renderer names the check
-- without callers passing bare strings.
newtype ByteCheckLabel = ByteCheckLabel { unByteCheckLabel :: String }
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- renderApplyError
----------------------------------------------------------------------------

renderCursorKind :: CursorKind -> String
renderCursorKind SourceCursor = "source-relative"
renderCursorKind TargetCursor = "target-relative"

renderApplyError :: ApplyError -> String

renderApplyError (ApplyCursorUnderflow cursorKind actionIndex cursor) =
  "at step #" ++ show (unActionIndex actionIndex) ++ ": "
  ++ renderCursorKind cursorKind ++ " cursor underflowed (value "
  ++ show (unSignedOffset cursor) ++ ")"

renderApplyError (ApplySourceReadOutOfBounds actionIndex readEndOffset sourceSize) =
  "at step #" ++ show (unActionIndex actionIndex)
  ++ ": input read would end at offset 0x"
  ++ showHex (unOffset readEndOffset) ""
  ++ " but input is " ++ show (unFileSize sourceSize) ++ " bytes"

renderApplyError (ApplyTargetReadUnwritten actionIndex (ReadOffset readOffset) (WritePosition writePosition)) =
  "at step #" ++ show (unActionIndex actionIndex)
  ++ ": TargetCopy read at offset 0x"
  ++ showHex (unOffset readOffset) ""
  ++ " references position at or past current write position 0x"
  ++ showHex (unOffset writePosition) ""

renderApplyError (ApplyWritesPastTarget actionIndex (RequestedLength requestedLength) (RemainingLength remainingLength)) =
  "at step #" ++ show (unActionIndex actionIndex)
  ++ ": action of length " ++ show (unLength requestedLength)
  ++ " would write past output ("
  ++ show (unLength remainingLength) ++ " bytes remaining)"

renderApplyError (ApplyTargetUnderfilled (WritePosition cursor) (ExpectedSize expectedSize)) =
  "output under-filled ("
  ++ show (unOffset cursor) ++ " of "
  ++ show (unFileSize expectedSize) ++ " bytes written before action stream exhausted)"

renderApplyError (ApplyNegativeRecordOffset actionIndex offset) =
  "record " ++ show (unActionIndex actionIndex)
  ++ " has negative offset " ++ show (unOffset offset)

renderApplyError (ApplyReplaceGrowsFile actionIndex offset (RequestedLength payloadLength) sourceSize) =
  "record " ++ show (unActionIndex actionIndex)
  ++ ": Replace at offset 0x" ++ showHex (unOffset offset) ""
  ++ " writes " ++ show (unLength payloadLength) ++ " bytes"
  ++ ", which would extend past the source size of "
  ++ show (unFileSize sourceSize) ++ " bytes"
  ++ " (PPF4 Replaces cannot grow the file; use Append records)"

----------------------------------------------------------------------------
-- renderSlapError
----------------------------------------------------------------------------

renderSlapError :: SlapError -> String

renderSlapError UnrecognizedFormat =
  "unknown patch format"

renderSlapError (AmbiguousDetection labels) =
  "ambiguous format: could be "
  ++ commaList (map formatLabelName labels)

renderSlapError (InputTooShort label (RequiredLength needed) (ActualLength actual)) =
  formatLabelName label ++ ": input too short (need "
  ++ show (unLength needed) ++ " bytes, have "
  ++ show (unLength actual) ++ ")"

renderSlapError (BadMagic label (ActualMagic actualBytes)) =
  "not a " ++ formatLabelName label ++ " file (bad magic: "
  ++ show actualBytes ++ ")"

renderSlapError (BadVersion label (FoundVersion versionByte)) =
  formatLabelName label ++ ": unsupported version "
  ++ show versionByte

renderSlapError (UnsupportedSubformat label subformat) =
  formatLabelName label ++ ": unsupported subformat: "
  ++ subformat

renderSlapError (TruncatedRecord label recordIndex needed available) =
  formatLabelName label ++ ": record " ++ show recordIndex
  ++ " truncated (need " ++ show (unLength needed)
  ++ " bytes, have " ++ show (unLength available) ++ ")"

renderSlapError (NegativeSize label name (ParsedSizeValue value)) =
  formatLabelName label ++ ": negative "
  ++ fieldNameLabel name ++ ": " ++ show value

renderSlapError (DecompressionFailed failure) =
  renderDecompressionFailure failure

renderSlapError (RecordExceedsAddressableRange label recordIndex (ActualOffset endOffset) (MaxOffset maxEndOffset)) =
  formatLabelName label ++ ": record " ++ show (unActionIndex recordIndex)
  ++ " ends at offset 0x" ++ showHex (unOffset endOffset) ""
  ++ ", exceeding the variant's maximum addressable end 0x"
  ++ showHex (unOffset maxEndOffset) ""

renderSlapError (MalformedRecordField label recordIndex name) =
  formatLabelName label ++ ": record " ++ show (unActionIndex recordIndex)
  ++ " has malformed " ++ fieldNameLabel name

renderSlapError (UnrecognizedTrailer label (TrailerMarker markerBytes) (ActualLength actualLength)) =
  formatLabelName label ++ ": unrecognized trailing bytes after "
  ++ renderTrailerMarkerName markerBytes ++ " marker ("
  ++ show (unLength actualLength) ++ " bytes)"

renderSlapError (PatchCRCMismatch label (ExpectedCRC32 stored) (ActualCRC32 computed)) =
  formatLabelName label ++ ": patch CRC mismatch (stored "
  ++ showCRC32 stored ++ ", computed " ++ showCRC32 computed ++ ")"

renderSlapError (TrailingMagicMismatch label (ExpectedMagic expected) (ActualMagic actual)) =
  formatLabelName label ++ ": trailing magic mismatch (expected "
  ++ show expected ++ ", found " ++ show actual ++ ")"

renderSlapError (UnknownFlag label name (RawFlagByte flagByte)) =
  formatLabelName label ++ ": unknown "
  ++ fieldNameLabel name ++ " flag: 0x"
  ++ showHex flagByte ""

renderSlapError (UnsupportedEncodingMethod label (EncodingMethodByte methodByte)) =
  formatLabelName label ++ ": unsupported encoding method: 0x"
  ++ showHex methodByte ""

renderSlapError (NINJA2UnrecognizedPatchEncoding byte) =
  "NINJA2 PATCH_ENC byte is 0x" ++ padHex 2 byte
    ++ " (expected 0 for system or 1 for UTF-8); the NINJA2 spec defines no other values, "
    ++ "and slap will not guess how to decode text fields under an undefined encoding"

renderSlapError (MalformedTextField label detail) =
  formatLabelName label ++ ": malformed text: " ++ detail

renderSlapError (EntryOutsideBlock label detail) =
  formatLabelName label ++ ": entry outside block: " ++ detail

renderSlapError (ParseError label message) =
  formatLabelName label ++ ": " ++ message

renderSlapError (UnsupportedXDelta1Shape description) =
  formatLabelName LabelXDelta1
  ++ ": unsupported source-list shape: " ++ description
  ++ " (xdelta1 admits []/[data]/[file]/[data, file] per"
  ++ " xdelta-1.1.4/xdmain.c:1741-1768 and the xdelta.1 manpage)"

renderSlapError (XDelta1InstructionIndexOutOfRange index shape) =
  formatLabelName LabelXDelta1
  ++ ": instruction index " ++ show index
  ++ " out of range for source shape " ++ renderXDelta1ShapeName shape

renderSlapError (NegativeTargetSize label size) =
  formatLabelName label ++ ": negative output size: "
  ++ show (unFileSize size)

renderSlapError (ApplyFailed label applyErr) =
  formatLabelName label ++ " apply: " ++ renderApplyError applyErr

renderSlapError (UndoFailed label applyErr) =
  formatLabelName label ++ " undo: " ++ renderApplyError applyErr

renderSlapError (CannotExpressTargetShrinkage label (ActualSize sourceSize) (ExpectedSize targetSize)) =
  formatLabelName label ++ ": cannot express an output file smaller than the input"
  ++ " (input: 0x" ++ showHex (unFileSize sourceSize) ""
  ++ " bytes, output: 0x" ++ showHex (unFileSize targetSize) ""
  ++ " bytes); this format has no truncation marker"

renderSlapError (UPSUnencodeablePair label reason) =
  formatLabelName label ++ ": cannot encode pair: "
  ++ renderUnencodeabilityReason reason

renderSlapError (NarrowingError nf) = renderNarrowingFailure nf

renderSlapError (FileExceedsAddressableRange label (ActualSize actualSize) (MaxAddressableSize maxSize)) =
  formatLabelName label ++ ": input file is "
  ++ show (unFileSize actualSize) ++ " bytes, exceeding the host platform's "
  ++ show (unFileSize maxSize) ++ "-byte addressable range"

renderSlapError (SentinelCollisionUnfixable label (SentinelOffset sentinel)) =
  formatLabelName label ++ ": hunk offset 0x"
  ++ showHex (unOffset sentinel) ""
  ++ " collides with trailer sentinel and cannot be shifted"
  ++ " (no preceding source byte available to prepend)"

renderSlapError (SourceTooSmallForPPF2Validation label
                                                 (ActualSize sourceSize)
                                                 (ExpectedSize minimumSize)) =
  formatLabelName label ++ ": source file is "
  ++ show (unFileSize sourceSize) ++ " bytes; PPF2 requires at least "
  ++ show (unFileSize minimumSize) ++ " bytes ("
  ++ "the validation block samples 1024 bytes from offset 0x9320,"
  ++ " so anything below 0x9720 has no block to embed)"

renderSlapError (FieldTooLong label name (EncodedLength encodedLength) (MaxLength maxLength)) =
  formatLabelName label ++ ": " ++ fieldNameLabel name
  ++ " too long (" ++ show (unLength encodedLength)
  ++ " bytes, maximum " ++ show (unLength maxLength) ++ ")"

renderSlapError (EncodingFailure label name detail) =
  formatLabelName label ++ ": failed to encode "
  ++ fieldNameLabel name ++ ": " ++ detail

renderSlapError (MissingRequiredField label field) =
  formatLabelName label ++ " requires " ++ fieldName field
  ++ " but source patch doesn't provide it"

renderSlapError (ApplyOutputFieldsWouldBeDropped label drops) =
  "cannot convert to " ++ formatLabelName label ++ ": "
  ++ renderApplyOutputDrops label drops

renderSlapError (DiffRequiresSource label) =
  formatLabelName label
  ++ " requires source+target diff data\nuse --with INPUT"

renderSlapError (MetadataFieldRejected fields target) =
  let renderOne field =
        "--" ++ metadataFieldFlagName field
        ++ " (" ++ metadataFieldName field ++ ")"
  in case NonEmpty.toList fields of
       [single] ->
         "--" ++ metadataFieldFlagName single ++ " is not accepted by "
         ++ formatLabelName target
         ++ " (the " ++ metadataFieldName single ++ " field is not part of this format)"
       many ->
         formatLabelName target
         ++ " does not accept these flags:"
         ++ concatMap (\field -> "\n  - " ++ renderOne field) many

renderSlapError (ConstraintNotSupported constraints target) =
  let renderOne c =
        "--" ++ constraintFlagName c ++ " (" ++ constraintName c ++ ")"
  in case NonEmpty.toList constraints of
       [single] ->
         "the " ++ formatLabelName target
         ++ " format does not support --" ++ constraintFlagName single
         ++ " (" ++ constraintName single ++ ")"
       many ->
         "the " ++ formatLabelName target
         ++ " format does not support these constraints:"
         ++ concatMap (\c -> "\n  - " ++ renderOne c) many

renderSlapError (DialectNotSupported axes target) =
  let renderOne d =
        "--" ++ dialectFlagName d ++ " (" ++ dialectName d ++ ")"
  in case NonEmpty.toList axes of
       [single] ->
         "the " ++ formatLabelName target
         ++ " format does not have a " ++ dialectName single
         ++ " axis (--" ++ dialectFlagName single ++ ")"
       many ->
         "the " ++ formatLabelName target
         ++ " format does not have these dialect axes:"
         ++ concatMap (\d -> "\n  - " ++ renderOne d) many

renderSlapError (TruncationViolatesSMCShape size) =
  "--" ++ constraintFlagName SMCShapeConstraint
  ++ ": output size " ++ show (unFileSize size)
  ++ " bytes does not satisfy (size & 0xFFF) == 0x200; "
  ++ "the resulting IPS patch's truncation marker would be rejected by SNESTool"

renderSlapError (VerificationFatal warning) =
  renderSlapWarning warning ++ "\n  use --no-verify to proceed anyway"

----------------------------------------------------------------------------
-- renderDecompressionFailure
----------------------------------------------------------------------------

-- | The compression algorithm in flight at a given failure site.
-- Implicit per constructor for sites with fixed algorithms; for
-- VCDIFF (when added), reads the algorithm parameter.  Today's
-- only consumer is the future 'VCDIFFSectionFailed' arm; the
-- exhaustive match is the seam that fires '-Wincomplete-patterns'
-- when a new 'DecompressionFailure' constructor lands.
decompressionAlgorithm :: DecompressionFailure -> CompressionAlgorithm
decompressionAlgorithm Yay0WrapperFailed{}        = Yay0
decompressionAlgorithm NINJA1Failed{}             = Zlib
decompressionAlgorithm XDelta1Failed{}            = Gzip
decompressionAlgorithm BSDiffSectionFailed{}      = Bzip2

-- | Display name for a 'CompressionAlgorithm'.  Used by the future
-- 'VCDIFFSectionFailed' renderer arm; the four fixed-algorithm
-- arms render the algorithm name as a literal in their site
-- description.  Exhaustive over 'CompressionAlgorithm' so that
-- adding a new compression algorithm fires '-Wincomplete-patterns'
-- here.
compressionAlgorithmName :: CompressionAlgorithm -> String
compressionAlgorithmName Zlib  = "zlib"
compressionAlgorithmName Gzip  = "gzip"
compressionAlgorithmName Bzip2 = "bzip2"
compressionAlgorithmName Yay0  = "Yay0"
compressionAlgorithmName DJW   = "DJW"
compressionAlgorithmName LZMA  = "LZMA"
compressionAlgorithmName FGK   = "FGK"

bsDiffSectionName :: BSDiffSection -> String
bsDiffSectionName BSDiffControl = "control"
bsDiffSectionName BSDiffDiff    = "diff"
bsDiffSectionName BSDiffExtra   = "extra"

-- | Render a decompression failure as a user-facing line.  Each arm
-- supplies its site description as a literal — NINJA1's description
-- contains the word "zlib" because NINJA1 uses zlib, and that fact
-- is restated at the renderer rather than threaded through the
-- 'compressionAlgorithmName' indirection.  When 'VCDIFFSectionFailed'
-- lands its arm will need 'compressionAlgorithmName' because the
-- algorithm genuinely varies; today's four arms have fixed
-- algorithms and read more directly with literals.
renderDecompressionFailure :: DecompressionFailure -> String
renderDecompressionFailure failure = case failure of
  Yay0WrapperFailed       cause -> render "Yay0 wrapper"        cause
  NINJA1Failed            cause -> render "NINJA1 zlib payload" cause
  XDelta1Failed           cause -> render "XDelta1 gzip body"   cause
  BSDiffSectionFailed sec cause -> render
    ("BSDiff " ++ bsDiffSectionName sec ++ " bzip2 section") cause
  where
    render siteName (DecompressionCause msg) =
      siteName ++ ": decompression failed: " ++ msg

----------------------------------------------------------------------------
-- renderNarrowingFailure
----------------------------------------------------------------------------

renderNarrowingFailure :: NarrowingFailure -> String
renderNarrowingFailure (OffsetExceedsBound label (ActualOffset actual) (MaxOffset maxOffset)) =
  formatLabelName label ++ ": hunk offset 0x"
  ++ showHex (unOffset actual) ""
  ++ " exceeds maximum offset 0x"
  ++ showHex (unOffset maxOffset) ""
renderNarrowingFailure (FieldValueExceedsBound label field actual maxValue) =
  formatLabelName label
  ++ " " ++ fieldNameLabel field
  ++ " field value " ++ show actual
  ++ " exceeds the wire-format maximum of " ++ show maxValue

----------------------------------------------------------------------------
-- renderSlapWarning
----------------------------------------------------------------------------

renderSlapWarning :: SlapWarning -> String

renderSlapWarning (EmptyPatch _label unit) =
  "empty patch (0 " ++ unit ++ ")"

renderSlapWarning (NoEOFMarker _label) =
  "no EOF marker (patch may be truncated)"

renderSlapWarning (ZeroCountRLERecord label actionIndex) =
  "note: " ++ formatLabelName label
  ++ ": zero-count RLE record at position " ++ show (unActionIndex actionIndex)
  ++ " (accepted as no-op)"

renderSlapWarning NegativeZeroInBPS =
  "note: " ++ formatLabelName LabelBPS
  ++ ": signed-delta varint encoded zero as 0x81 (non-canonical;"
  ++ " 0x80 is the canonical form)"

renderSlapWarning (OverlappingRecords label (OverlapCount pairCount)) =
  "note: " ++ formatLabelName label
  ++ ": " ++ show pairCount
  ++ (if pairCount == 1 then " overlapping record pair"
                        else " overlapping record pairs")
  ++ " (later writes clobber earlier; unusual)"

renderSlapWarning (UnsortedRecords label actionIndex) =
  "note: " ++ formatLabelName label
  ++ ": record at position " ++ show (unActionIndex actionIndex)
  ++ " has a lower offset than the record before it"
  ++ " (unsorted records; applied in wire order)"

renderSlapWarning (IPS32TrailingBytes label (Length n)) =
  "note: " ++ formatLabelName label
  ++ ": dropped " ++ show n ++ " trailing bytes after EEOF marker"

renderSlapWarning (IPSTruncationMarkerHonored label
    (DeclaredTargetSize declared) (NaturalTargetSize natural)) =
  formatLabelName label
  ++ " apply: honored truncation marker (declared "
  ++ show (unFileSize declared) ++ " bytes, natural "
  ++ show (unFileSize natural) ++ " bytes)"

renderSlapWarning (IPSRecordsClippedByMarker label
    (ClippedRecordCount count) firstIndex (MarkerOvershootBytes overshoot)) =
  formatLabelName label ++ " apply: "
  ++ show count
  ++ (if count == 1 then " record" else " records")
  ++ " clipped by truncation marker (first at step #"
  ++ show (unActionIndex firstIndex) ++ ", "
  ++ show (unLength overshoot)
  ++ (if unLength overshoot == 1 then " byte" else " bytes")
  ++ " total clipped)"

renderSlapWarning (IPSTruncationMarkerIgnored label
    (DeclaredTargetSize declared) (NaturalTargetSize natural)) =
  formatLabelName label
  ++ " apply: ignored truncation marker (declared "
  ++ show (unFileSize declared) ++ " bytes, natural "
  ++ show (unFileSize natural) ++ " bytes; declared > natural means the marker would grow the output, which slap does not honor)"

renderSlapWarning (APSN64UnrecognizedCountry byte) =
  "note: " ++ formatLabelName LabelAPSN64
  ++ ": country code 0x" ++ padHex 2 byte
  ++ " is not a recognized N64 region code; preserving the byte verbatim"

renderSlapWarning (FieldDropped field droppedValue) =
  let rendered = renderDroppedValue droppedValue
  in if null rendered
     then "note: dropping " ++ fieldName field
     else "note: dropping " ++ fieldName field ++ ": " ++ rendered

renderSlapWarning (UndoDataDropped recordCount) =
  "note: dropping undo data (" ++ show recordCount ++ " records)"

renderSlapWarning ValidationBlockDropped =
  "note: dropping validation block (1024 bytes)"

renderSlapWarning (DisabledEntriesDropped entryCount) =
  "note: dropping " ++ show entryCount ++ " disabled entries"

renderSlapWarning BlockDescriptionsDropped =
  "note: dropping block descriptions"

renderSlapWarning (MetadataDropped byteCount) =
  "note: dropping metadata (" ++ show byteCount ++ " bytes)"

renderSlapWarning (DefaultRomType _label) =
  "note: assuming ROM type RAW (override with --rom-type)"

renderSlapWarning (DefaultImageType _label) =
  "note: assuming image type BIN (override with --image-type gi for GI disc images)"

renderSlapWarning IncludingUndoByDefault =
  "note: including undo data (omit with --no-undo)"

renderSlapWarning IncludingValidationByDefault =
  "note: including validation block (omit with --no-validate)"

renderSlapWarning (SourceHashesMissing _label) =
  "note: input verification hashes not available (populate with --with INPUT)"

renderSlapWarning (FieldTruncated label name (OriginalLength original) (TruncatedLength truncated)) =
  "note: " ++ formatLabelName label ++ " "
  ++ fieldNameLabel name ++ " truncated to fit "
  ++ show (unLength truncated) ++ "-byte field (was "
  ++ show (unLength original) ++ " bytes)"

renderSlapWarning (EncodingGap fromLabel toLabel) =
  "note: " ++ formatLabelName fromLabel
  ++ " text was stored with known encoding; "
  ++ formatLabelName toLabel
  ++ " has no encoding flag; writing bytes as-is"

renderSlapWarning (PlatformNotAvailable label name) =
  "note: platform " ++ name ++ " not available in " ++ formatLabelName label ++ "; using Raw"

renderSlapWarning (PlatformAmbiguous label combined chosen override) =
  "note: " ++ formatLabelName label ++ " ROM type " ++ combined
  ++ " is ambiguous; defaults to " ++ chosen
  ++ " on conversion (override with --rom-type " ++ override ++ ")"

renderSlapWarning (ApplyOOBBlocksSkipped label (OOBBlockCount count) firstIndex (OOBOvershootBytes overshoot) declaredSize) =
  formatLabelName label ++ " apply: "
  ++ show count ++ plural count " block writes" " blocks write"
  ++ " past declared output size ("
  ++ show (unFileSize declaredSize) ++ " bytes); first at step #"
  ++ show (unActionIndex firstIndex) ++ ", "
  ++ show (unLength overshoot) ++ plural (unLength overshoot) " byte" " bytes"
  ++ " total overshoot — clipped to output bounds"
  where plural n singular pluralForm = if n == 1 then singular else pluralForm

renderSlapWarning (SubformatConverted label fromSub toSub) =
  "note: " ++ formatLabelName label ++ " "
  ++ fromSub ++ " converted to " ++ toSub

renderSlapWarning OffsetShiftApplied =
  "note: PCHTXT offset_shift applied to absolute offsets; output has no @flag directive"

----------------------------------------------------------------------------
-- Verification: source/target integrity check mismatches
----------------------------------------------------------------------------

renderSlapWarning (VerificationCRCMismatch side (ExpectedCRC32 expected) (ActualCRC32 actual)) =
  verificationSideLabel side ++ " CRC mismatch (expected 0x"
  ++ showCRC32 expected ++ ", got 0x" ++ showCRC32 actual ++ ")"

renderSlapWarning (VerificationHashMismatch side algorithm) =
  verificationSideLabel side ++ " " ++ hashAlgorithmLabel algorithm ++ " mismatch"

renderSlapWarning (VerificationAdler32Mismatch windowOffset (ExpectedAdler32 expected) (ActualAdler32 actual)) =
  "Adler32 mismatch at window 0x" ++ padHex 8 (unOffset windowOffset)
  ++ " (expected 0x" ++ showAdler32 expected
  ++ ", got 0x" ++ showAdler32 actual ++ ")"

renderSlapWarning (VerificationFileSizeMismatch side (ExpectedSize expectedSize) (ActualSize actualSize)) =
  verificationSideLabel side ++ " file size mismatch (expected "
  ++ show (unFileSize expectedSize) ++ " bytes, got "
  ++ show (unFileSize actualSize) ++ " bytes)"

renderSlapWarning (VerificationBlockCRC16Mismatch side blockOffset) =
  verificationSideLabel side ++ " CRC16 mismatch at 0x" ++ padHex 8 (unOffset blockOffset)

renderSlapWarning (VerificationPPFBlockMismatch blockOffset) =
  "validation block mismatch at 0x" ++ padHex 8 (unOffset blockOffset)

renderSlapWarning (VerificationFileSizeAdvisory (ExpectedSize expectedSize) (ActualSize actualSize)) =
  "file size mismatch (expected " ++ show (unFileSize expectedSize)
  ++ ", got " ++ show (unFileSize actualSize) ++ ")"

renderSlapWarning (VerificationSourceBytesMismatch (ByteCheckLabel label) checkOffset) =
  label ++ " mismatch at 0x" ++ padHex 8 (unOffset checkOffset)

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Render the bracketed shape name for an 'XDelta1SourceShape'.
-- Used by 'XDelta1InstructionIndexOutOfRange' so the renderer can
-- name the (small) shape the bad index was found in. Matches the
-- vocabulary used by 'UnsupportedXDelta1Shape' so a reader who sees
-- both errors gets the same names for the same shapes.
renderXDelta1ShapeName :: XDelta1SourceShape -> String
renderXDelta1ShapeName XDelta1NoSources       = "[]"
renderXDelta1ShapeName (XDelta1DataOnly _)    = "[data]"
renderXDelta1ShapeName (XDelta1FileOnly _)    = "[file]"
renderXDelta1ShapeName XDelta1DataAndFile{}   = "[data, file]"

renderUnencodeabilityReason :: UnencodeabilityReason -> String
renderUnencodeabilityReason UPSLastByteDiffers =
  "target's final byte differs from source (with virtual zero-padding);"
  ++ " no terminator byte can be placed past target end"
renderUnencodeabilityReason UPSSourceTailNonZero =
  "source has non-zero bytes past target size;"
  ++ " these cannot be represented in a UPS patch"

-- | Render a trailer marker's raw bytes for inclusion in an error
-- message. The 'StandardIPS' and 'IPS32' markers are ASCII-printable
-- (@"EOF"@, @"EEOF"@), so the common case is the literal string. For
-- a hypothetical future trailer marker that contained any non-
-- printable byte, the renderer falls back to a hex dump rather than
-- emitting raw control characters into the error stream.
renderTrailerMarkerName :: ByteString -> String
renderTrailerMarkerName = renderPrintableASCIIOrHex

-- | Render the apply-output-field-drop refusal body. The single-drop
-- case (today's only case, 'FieldTruncation') produces one clean sentence;
-- the multi-drop case (trivially available if 'affectsApplyOutput'
-- grows) bullets each field on its own line so nothing gets lost.
renderApplyOutputDrops :: FormatLabel -> [(PatchField, [FormatLabel])] -> String
renderApplyOutputDrops target [singleDrop] = renderOneDrop target singleDrop
renderApplyOutputDrops target manyDrops =
  concatMap (\drop_ -> "\n  - " ++ renderOneDrop target drop_) manyDrops

renderOneDrop :: FormatLabel -> (PatchField, [FormatLabel]) -> String
renderOneDrop target (field, preservers) =
  "the source patch declares a " ++ fieldName field
  ++ ", and " ++ formatLabelName target
  ++ " has no representation for it. " ++ renderPreservers field preservers

renderPreservers :: PatchField -> [FormatLabel] -> String
renderPreservers field [] =
  "No target format preserves " ++ fieldName field ++ "."
renderPreservers field preservers =
  "Targets that preserve " ++ fieldName field ++ ": "
  ++ commaSeparated (map formatLabelName preservers) ++ "."

commaSeparated :: [String] -> String
commaSeparated []      = ""
commaSeparated [x]     = x
commaSeparated (x:xs)  = x ++ ", " ++ commaSeparated xs

commaList :: [String] -> String
commaList []     = ""
commaList [x]    = x
commaList [x, y] = x ++ " or " ++ y
commaList items  = concatMap (++ ", ") (init items) ++ "or " ++ last items
