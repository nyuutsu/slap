{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | The cross-format nouns of slap's status language — the payload types its errors and advisories carry.
module Slap.Status.Vocabulary
  ( -- * Extraction and dropped values
    ExtractionSubject(..)
  , DroppedValue(..)
  , DroppedDescriptionText(..)
  , renderDroppedValue
    -- * Empty-patch units
  , EmptyUnit(..)
  , emptyUnitLabel
    -- * Counts and overshoots
  , OverlapCount(..)
  , ClippedRecordCount(..)
  , OOBBlockCount(..)
  , CarriedFileCount(..)
  , UndoRecordCount(..)
  , MarkerOvershootBytes(..)
  , OOBOvershootBytes(..)
    -- * Apply direction
  , ApplyDirection(..)
  , directionVerb
    -- * Verification payloads
  , VerificationSide(..)
  , verificationSideLabel
  , HashAlgorithm(..)
  , hashAlgorithmLabel
  , DeclaredCheckKind(..)
  , declaredCheckKindNoun
  , ExpectedAdler32(..)
  , ActualAdler32(..)
  , ByteCheckLabel(..)
    -- * Compression
  , CompressionAlgorithm(..)
  , compressionAlgorithmName
    -- * Per-format header malformations
  , ControlSectionSize(..)
  , DiffSectionSize(..)
  , TargetSectionSize(..)
  , BSDiffHeaderMalformation(..)
  , APSN64HeaderMalformation(..)
  , NINJA1SubformatIdentifier(..)
  , NINJA1Malformation(..)
  , NINJA1SubformatConversion(..)
    -- * ROM-image normalization
  , NormalizationStep(..)
  , SNESInterleaveLayout(..)
  , NormalizedImageRole(..)
  , normalizedImageRoleLabel
  , NormalizationSkipReason(..)
  , RestoredContent(..)
    -- * Verbatim wire text
  , LineText(..)
  , OffsetTokenText(..)
  , ChecksumTokenText(..)
    -- * Shared phrases
  , slapAddressableCeiling
  ) where

import Slap.Checksum (CRC32, Adler32, MD5Hash(..), SHA1Hash(..), showCRC32)
import Slap.Display.Common (renderAsText)
import Slap.Display.Primitives (hexByteString)
import Slap.FieldName (FieldName)
import Slap.JSON.Bytes (BytesAsBase64(..))
import Slap.Measure (Length, FileSize(..))

import Data.Aeson (ToJSON)
import Data.Bits (finiteBitSize)
import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.Text (Text)
import Data.Word (Word8)
import GHC.Generics (Generic, Generically(..))

-- | The numeral every addressable-range refusal names — @2^63-1@ on a 64-bit host.
-- Derived from the width of 'Int' so a 32-bit build tells its own truth.
slapAddressableCeiling :: Text
slapAddressableCeiling = "2^" <> renderAsText (finiteBitSize (0 :: Int) - 1) <> "-1"

-- | Which @info@ extraction found nothing to write, for 'Slap.Status.NothingToExtract'.
data ExtractionSubject
  = EmbeddedMetadataSubject
  | FileIdDizSubject
  deriving (Show, Eq, Generic)
  deriving (ToJSON) via Generically ExtractionSubject

data DroppedValue
  = DroppedCRC CRC32
  | DroppedMD5 MD5Hash
  | DroppedSHA1 SHA1Hash
  | DroppedDescription DroppedDescriptionText
  | DroppedSize FileSize
  | DroppedEmpty
  deriving (Show, Eq, Generic)
  deriving (ToJSON) via Generically DroppedValue

newtype DroppedDescriptionText = DroppedDescriptionText
  { unDroppedDescriptionText :: Text }
  deriving (Show, Eq)
  deriving newtype (ToJSON)

renderDroppedValue :: DroppedValue -> Text
renderDroppedValue (DroppedCRC crc)                                = "0x" <> showCRC32 crc
renderDroppedValue (DroppedMD5 hash)                               = hexByteString (unMD5Hash hash)
renderDroppedValue (DroppedSHA1 hash)                              = hexByteString (unSHA1Hash hash)
renderDroppedValue (DroppedDescription (DroppedDescriptionText t)) = "\"" <> t <> "\""
renderDroppedValue (DroppedSize size)                              = renderAsText (unFileSize size) <> " bytes"
renderDroppedValue DroppedEmpty                                    = ""

-- | The semantic unit a patch enumerates, so 'Slap.Status.EmptyPatch' can name the right noun ("records", "blocks", "windows", ...).
data EmptyUnit
  = EmptyRecords
  | EmptyActions
  | EmptyBlocks
  | EmptyWindows
  | EmptyCommands
  | EmptyInstructions
  | EmptyEntries
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically EmptyUnit

emptyUnitLabel :: EmptyUnit -> Text
emptyUnitLabel EmptyRecords      = "records"
emptyUnitLabel EmptyActions      = "actions"
emptyUnitLabel EmptyBlocks       = "blocks"
emptyUnitLabel EmptyWindows      = "windows"
emptyUnitLabel EmptyCommands     = "commands"
emptyUnitLabel EmptyInstructions = "instructions"
emptyUnitLabel EmptyEntries      = "entries"

-- | The number of overlapping record pairs an IPS-family parse found.
-- Never zero: 'Slap.Status.OverlappingRecords' only fires when at least one pair exists.
newtype OverlapCount = OverlapCount { unOverlapCount :: Int }
  deriving (Eq, Ord, Show)
  deriving newtype (ToJSON)

-- | The number of IPS records clipped to fit a honored truncation marker.
-- Never zero: 'Slap.Status.IPSRecordsClippedByMarker' only fires when at least one record crossed the boundary.
newtype ClippedRecordCount = ClippedRecordCount { unClippedRecordCount :: Int }
  deriving (Eq, Ord, Show)
  deriving newtype (ToJSON)

-- | The number of UPS blocks whose write region extends past the declared target file size.
-- Never zero: 'Slap.Status.ApplyOOBBlocksSkipped' only fires when at least one block was out of bounds.
newtype OOBBlockCount = OOBBlockCount { unOOBBlockCount :: Int }
  deriving (Eq, Ord, Show)
  deriving newtype (ToJSON)

-- | How many files a patch bundles. Never one: 'Slap.Status.PatchCarriesMultipleFiles' only fires past the first.
newtype CarriedFileCount = CarriedFileCount { unCarriedFileCount :: Int }
  deriving (Eq, Ord, Show)
  deriving newtype (ToJSON)

-- | The number of undo records dropped when converting to a target format with no undo representation.
-- Emitted only when the source actually carried undo records.
newtype UndoRecordCount = UndoRecordCount { unUndoRecordCount :: Int }
  deriving (Eq, Ord, Show)
  deriving newtype (ToJSON)

-- | The total byte length lost across all records clipped by an honored IPS truncation marker — per-record overshoots, summed.
-- 'Semigroup' and 'Monoid' pass through to 'Length' so accumulating walks can use '<>' and 'mempty'.
newtype MarkerOvershootBytes = MarkerOvershootBytes { unMarkerOvershootBytes :: Length }
  deriving (Eq, Ord, Show, Semigroup, Monoid)
  deriving newtype (ToJSON)

-- | The UPS counterpart of 'MarkerOvershootBytes': the total byte length lost across blocks that extended past the declared target size.
newtype OOBOvershootBytes = OOBOvershootBytes { unOOBOvershootBytes :: Length }
  deriving (Eq, Ord, Show, Semigroup, Monoid)
  deriving newtype (ToJSON)

-- | Which direction an apply/undo operation ran in.
-- Tagged onto advisories that describe direction-dependent observations (such as 'Slap.Status.ApplyOOBBlocksSkipped',
-- whose count and overshoot are measured against the output the operation actually wrote: target_size forward, source_size reverse).
--
-- Not the CLI subcommand the user typed: @slap apply@ and @slap undo@ drive the two directions one-to-one,
-- but direction lives at the Format layer (each format's apply/undo functions know which they implement),
-- while subcommand selection lives at the Entry-point layer ('app/Main.hs').
data ApplyDirection
  = Forward  -- ^ The natural-direction operation: 'applyUPS', 'applyBPS', etc.
  | Reverse  -- ^ The inverse operation: 'undoUPS', 'undoBPS', etc.
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically ApplyDirection

-- | The user-facing verb for each direction: @"apply"@ and @"undo"@, the CLI's own words, not "forward" and "reverse".
directionVerb :: ApplyDirection -> Text
directionVerb Forward = "apply"
directionVerb Reverse = "undo"

-- | Which side of the apply a verification check fired against.
-- The constructors keep slap's source\/target vocabulary; the rendered labels track the CLI's input\/output.
data VerificationSide = SourceSide | TargetSide
  deriving (Show, Eq, Generic)
  deriving (ToJSON) via Generically VerificationSide

verificationSideLabel :: VerificationSide -> Text
verificationSideLabel SourceSide = "input"
verificationSideLabel TargetSide = "output"

data HashAlgorithm = MD5 | SHA1
  deriving (Show, Eq, Generic)
  deriving (ToJSON) via Generically HashAlgorithm

hashAlgorithmLabel :: HashAlgorithm -> Text
hashAlgorithmLabel MD5  = "MD5"
hashAlgorithmLabel SHA1 = "SHA1"

-- | The kind of a declared check, named so a message can say what a match actually rests on —
-- a held size check and a held SHA1 earn different sentences.
data DeclaredCheckKind
  = DeclaredCRC32
  | DeclaredMD5
  | DeclaredSHA1
  | DeclaredFileSize
  | DeclaredBlockCRC16
  | DeclaredValidationBlock
  | DeclaredByteComparison
  | DeclaredByteOrder
  | DeclaredWindowAdler32
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically DeclaredCheckKind

-- | The check vocabulary of match-side messages, in the mismatch warnings' own dialect ("input CRC mismatch").
declaredCheckKindNoun :: DeclaredCheckKind -> Text
declaredCheckKindNoun DeclaredCRC32           = "CRC"
declaredCheckKindNoun DeclaredMD5             = "MD5"
declaredCheckKindNoun DeclaredSHA1            = "SHA1"
declaredCheckKindNoun DeclaredFileSize        = "declared size"
declaredCheckKindNoun DeclaredBlockCRC16      = "block CRC16s"
declaredCheckKindNoun DeclaredValidationBlock = "validation block"
declaredCheckKindNoun DeclaredByteComparison  = "identifying bytes"
declaredCheckKindNoun DeclaredByteOrder       = "byte order"
declaredCheckKindNoun DeclaredWindowAdler32   = "window checksums"

-- | An Adler32 value a patch declared or stored — 'Slap.Checksum.ExpectedCRC32''s peer.
newtype ExpectedAdler32 = ExpectedAdler32 { unExpectedAdler32 :: Adler32 }
  deriving (Show, Eq)
  deriving newtype (ToJSON)

-- | An Adler32 value computed from the actual data — 'Slap.Checksum.ActualCRC32''s peer.
newtype ActualAdler32 = ActualAdler32 { unActualAdler32 :: Adler32 }
  deriving (Show, Eq)
  deriving newtype (ToJSON)

-- | The label of an advisory byte-range check ("N64 cart ID", "N64 country", "N64 CRC"), for 'Slap.Status.VerificationSourceBytesMismatch'.
newtype ByteCheckLabel = ByteCheckLabel { unByteCheckLabel :: Text }
  deriving (Show, Eq)
  deriving newtype (ToJSON)

-- | Every compression algorithm slap knows: four with fixed decompression sites,
-- plus xdelta3's secondary-compression catalog (DJW, LZMA, FGK).
data CompressionAlgorithm
  = Zlib | Gzip | Bzip2 | Yay0
  | DJW  | LZMA | FGK
  deriving (Show, Eq, Ord, Enum, Bounded, Generic)
  deriving (ToJSON) via Generically CompressionAlgorithm

compressionAlgorithmName :: CompressionAlgorithm -> Text
compressionAlgorithmName Zlib  = "zlib"
compressionAlgorithmName Gzip  = "gzip"
compressionAlgorithmName Bzip2 = "bzip2"
compressionAlgorithmName Yay0  = "Yay0"
compressionAlgorithmName DJW   = "DJW"
compressionAlgorithmName LZMA  = "LZMA"
compressionAlgorithmName FGK   = "FGK"

newtype ControlSectionSize = ControlSectionSize { unControlSectionSize :: Int64 } deriving (Eq, Show) deriving newtype (ToJSON)
newtype DiffSectionSize    = DiffSectionSize    { unDiffSectionSize    :: Int64 } deriving (Eq, Show) deriving newtype (ToJSON)
newtype TargetSectionSize  = TargetSectionSize  { unTargetSectionSize  :: Int64 } deriving (Eq, Show) deriving newtype (ToJSON)

-- | The structural failures slap raises when validating a BSDiff fixed-width header.
-- 'BSDiffNegativeHeaderSizes': at least one of the three section sizes decoded as negative.
-- The two overrun arms name the block whose declared size reaches past the end of the patch, carrying the distance in bytes;
-- 'Slap.BSDiff.Parse.parseBSDiff' judges them sequentially (control against the whole body, then diff against what control left),
-- each step a comparison that cannot wrap the way a summed bound could.
data BSDiffHeaderMalformation
  = BSDiffNegativeHeaderSizes !ControlSectionSize !DiffSectionSize !TargetSectionSize
  | BSDiffControlOverrunsPatch !Int64
  | BSDiffDiffOverrunsPatch !Int64
  | BSDiffTargetOverrunsData !Int64
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically BSDiffHeaderMalformation

-- | A header byte slap validates before the main wire-level walk and cannot accept:
-- a patch type other than simple or N64, or a record encoding other than 0, the only one slap can decode.
data APSN64HeaderMalformation
  = APSN64UnknownPatchType !Word8
  | APSN64UnsupportedEncoding !Word8
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically APSN64HeaderMalformation

-- | NINJA1's two-byte @subFormatIdentifier@ pair, as read.
newtype NINJA1SubformatIdentifier = NINJA1SubformatIdentifier { unNINJA1SubformatIdentifier :: ByteString }
  deriving (Eq, Show)
  deriving (ToJSON) via BytesAsBase64

-- | The NINJA1-format-specific malformations a textual-patch parser can refuse.
-- Each names a structural failure of the textual grammar.
-- The exception is 'NINJA1UnaddressableOffsetInTextRecord': a value the grammar admits but slap cannot carry.
-- The labeled newtypes (e.g. 'LineText') carry the offending wire bytes for the renderer.
data NINJA1Malformation
  = NINJA1EmptyTextualPatch
  | NINJA1InvalidOffsetInTextRecord OffsetTokenText
  | NINJA1UnaddressableOffsetInTextRecord OffsetTokenText
    -- ^ The offset token is clean hex but names a position past 'maxBound' :: 'Int'.
    -- Textual offsets have no width limit, so the parser decodes at 'Integer' and refuses rather than wrapping.
  | NINJA1MalformedChecksum FieldName ChecksumTokenText
    -- ^ A header checksum slot holds a token that is neither @"unk"@\/@"unk."@ nor a valid checksum for that slot.
    -- Such a token is refused rather than skipped or truncated into a wrong one; the 'FieldName' names the slot.
  | NINJA1MalformedTextRecord       LineText
  | NINJA1ExtraFieldsInTextRecord LineText
    -- ^ A textual record line carries more than the offset and payload the format's line has room for.
    -- The spec sheet writes that line as @OFFSET PATCH_BYTES@, two fields, and gives no third one a meaning;
    -- the reference applier binds the first two, and any beyond them go unused.
  | NINJA1InvalidHexPayloadInTextRecord LineText
    -- ^ A record's payload has a non-hex character or a lone trailing nibble, so it isn't the whole pairs of hex digits a text record must hold.
    -- Refused outright rather than decoded up to the fault, which would write a shorter span than the record declares.
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically NINJA1Malformation

-- | Which textual-to-binary decode 'Slap.Status.SubformatConverted' reports.
data NINJA1SubformatConversion
  = NINJA1TextToBinary
  | NINJA1CompressedTextToCompressedBinary
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically NINJA1SubformatConversion

-- | One canonicalization a ROM type's normalization procedure performed, carried by 'Slap.Status.RomImageNormalized'.
-- The header widths are fixed per arm (the iNES header is 16 bytes, the copier-era headers 512), so no arm carries a length.
-- The procedures live in "Slap.Normalize".
data NormalizationStep
  = StrippedINESHeader
  | StrippedFFEHeader
  | MergedUNIFChunks
  | StrippedSNESCopierHeader
  | StrippedNSRTHeader
  | DeinterleavedSNESHiROM SNESInterleaveLayout
  | ByteswappedN64Image
  | StrippedSmartCardHeader
  | DeinterleavedSMDImage
  | StrippedMagicSuperGriffinHeader
  | StrippedLynxHeader
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically NormalizationStep

-- | Which interleave layout a SNES HiROM deinterleave undid: the generic even/odd halves scheme,
-- or one of the three Game Doctor SF charts, keyed to exact image sizes (20, 24, 48 Mbit).
data SNESInterleaveLayout
  = EvenOddHalvesLayout
  | GD3Chart20MbitLayout
  | GD3Chart24MbitLayout
  | GD3Chart48MbitLayout
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SNESInterleaveLayout

-- | Which file a normalization advisory speaks about: the apply-side input, or one of the two files handed to create.
data NormalizedImageRole
  = NormalizedApplyInput
  | NormalizedCreateOriginal
  | NormalizedCreateModified
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically NormalizedImageRole

normalizedImageRoleLabel :: NormalizedImageRole -> Text
normalizedImageRoleLabel NormalizedApplyInput     = "input"
normalizedImageRoleLabel NormalizedCreateOriginal = "original"
normalizedImageRoleLabel NormalizedCreateModified = "modified"

-- | Why an image that matched one of its ROM type's shapes still could not be normalized:
-- the declared structure and the actual bytes disagree in a way the transform cannot bridge.
data NormalizationSkipReason
  = ImageShorterThanItsHeader
  | SMDBlocksNotWhole
  | SNESInterleavedBlocksNotWhole
  | UNIFChunkTableTruncated
  | N64ImageOddLength
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically NormalizationSkipReason

-- | What 'Slap.Status.RomImageContentRestored' put back into the output: a stripped header re-prepended
-- (carrying its width for the rendering), or patched data reinserted into the original UNIF chunk table.
data RestoredContent
  = RestoredHeaderPrefix Length
  | RestoredUNIFContainer
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically RestoredContent

-- | A line of textual-patch input, carried verbatim for a malformation diagnostic.
newtype LineText = LineText { unLineText :: Text }
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | A hex-offset token slice from a textual-patch line, carried verbatim for a malformation diagnostic.
newtype OffsetTokenText = OffsetTokenText { unOffsetTokenText :: Text }
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | A header checksum token, carried verbatim for a 'NINJA1MalformedChecksum' diagnostic.
newtype ChecksumTokenText = ChecksumTokenText { unChecksumTokenText :: Text }
  deriving (Eq, Show)
  deriving newtype (ToJSON)
