-- | Tests for the conversion contract system.
--
-- 'canConvert' decides whether a 'PatchContents' bundle carries
-- everything a target 'DirectConversionContract' requires. 'conversionNotes'
-- reports fields that are present in the source but can't be carried
-- through to the target. Together they enforce the principle that
-- conversion either preserves information or tells you what it drops.
--
-- These tests also exercise IPS/IPS32 sentinel collision detection,
-- which is a form of contract enforcement: some byte layouts can't
-- be encoded safely in IPS and must be rejected at the encoding
-- boundary.
module Props.Contracts (contractTests) where

import qualified Slap.IPS.Apply as IPS
import qualified Slap.IPS.Parse as IPS
import Slap.IPS.Types (IPSParseResult(..))

import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.Status (CreateResult(..), Parsed(..), SlapError(..), Outcome(..), renderSlapError, renderSlapAdvisory)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), FileSize(..), Hunk(..),
                     splitUndoHunkFromParsed,
                     SentinelOffset(..))
import Slap.Convert (PatchContents(..), DirectCreate(..), CreateFormat(..),
                      DirectConversionContract(..), UndoInclusion(..), VerificationInclusion(..),
                      noMetadataRequested, noConstraintsRequested, noDialectsRequested,
                      directConversionContract,
                      emptyContents, canConvert, convertDirect, conversionNotes)
import Slap.IPS.Types (emptyEBPMetadata)
import Slap.Narrow (NarrowingFailure(..))
import Slap.Create (createPatch)
import Slap.PatchField (PatchField(..))
import Slap.PlatformType (PlatformType(..))

import qualified Data.ByteString as ByteString
import qualified Data.Text as Text
import Slap.Text (EncodedText(..), EncodingName(..))
import Data.List (isPrefixOf)
import qualified Data.Set as Set
import Test.Tasty
import Test.Tasty.QuickCheck

import Props.Helpers

contractTests :: TestTree
contractTests = testGroup "Contracts"
  [ testProperty "canConvert-full" prop_canConvertFull
  , testProperty "no-surplus-no-notes" prop_noSurplusNoNotes
  , testProperty "ninja1-accepts-empty" prop_ninja1AcceptsEmpty
  , testProperty "apsn64-rejects-empty" prop_apsn64RejectsEmpty
  , testProperty "ppf3-undo-rejects-empty" prop_ppf3UndoRejectsEmpty
  , testProperty "ppf3-validate-rejects-empty" prop_ppf3ValidateRejectsEmpty
  , testProperty "ips-sentinel-collision-direct" prop_ipsSentinelDirect
  , testProperty "ips32-sentinel-collision-direct" prop_ips32SentinelDirect
  , testProperty "ips-sentinel-split-direct" prop_ipsSentinelSplitDirect
  , testProperty "ips32-sentinel-split-direct" prop_ips32SentinelSplitDirect
  , testProperty "ips-sentinel-with-source" prop_ipsSentinelWithSource
  , testProperty "ips-negative-offset-convert-refused" prop_ipsNegativeOffsetConvertRefused
  ]

-- | Direct formats that go through buildContents -> encodeDirect.
directFormats :: [DirectCreate]
directFormats =
  [CreateIPS, CreateIPS32, CreateEBP, CreatePPF3, CreateNINJA1, CreatePMSR, CreateAPSN64]

-- | PatchContents with every field populated.
fullContents :: PatchContents
fullContents = PatchContents
  { contentsRecords     = [Hunk (Offset 0) (ByteString.pack [0xFF])]
  , contentsDescription = Just (EncodedText EncodingUtf8 (Text.pack "test"))
  , contentsSourceCRC32 = Just (CRC32 0xDEADBEEF)
  , contentsSourceMD5   = Just (MD5Hash (ByteString.replicate 16 0xAA))
  , contentsSourceSHA1  = Just (SHA1Hash (ByteString.replicate 20 0xBB))
  , contentsDestinationSize    = Just (FileSize 1024)
  , contentsValidation  = Just (ByteString.replicate 1024 0)
  , contentsUndoData    = Just [splitUndoHunkFromParsed (Offset 0) (ByteString.pack [0x00]) (ByteString.pack [0xFF])]
  , contentsTruncation  = Just (FileSize 512)
  , contentsEBPMetadata = Just emptyEBPMetadata
  , contentsRomType     = Just PlatformRaw
  , contentsImageType   = Nothing
  , contentsAPSN64ImageFormat = Nothing
  , contentsFileIdDiz   = Nothing
  , contentsNINJA1Compression = Nothing
  , contentsMetadata = Nothing
  }

-- | canConvert succeeds for every direct format when all fields it
-- accepts are present.  Apply-output-affecting fields that the target
-- doesn't accept (today only 'FieldTruncation' for targets other than IPS)
-- are stripped before the check: their presence would correctly make
-- 'canConvert' refuse with 'ApplyOutputFieldsDropped', so this test
-- only covers formats' accepted-field surface.
prop_canConvertFull :: Property
prop_canConvertFull = conjoin
  [ counterexample (show format) $
      canConvert (limitToAccepted format) (directConversionContract format IncludeUndoData IncludeVerification) === Right ()
  | format <- directFormats
  ]
  where
    limitToAccepted format =
      let contract = directConversionContract format IncludeUndoData IncludeVerification
          kept = contractRequiredFields contract `Set.union` contractAcceptedFields contract
      in fullContents
        { contentsTruncation = if FieldTruncation `Set.member` kept
                                then contentsTruncation fullContents
                                else Nothing
        }

-- | No dropped-field notes when provides exactly matches required + accepted.
prop_noSurplusNoNotes :: Property
prop_noSurplusNoNotes = conjoin
  [ counterexample (show format) $
      let contract = directConversionContract format IncludeUndoData IncludeVerification
          kept = contractRequiredFields contract `Set.union` contractAcceptedFields contract
          trimmed = fullContents
            { contentsDescription = if FieldDescription `Set.member` kept then contentsDescription fullContents else Nothing
            , contentsSourceCRC32 = if FieldSourceCRC32 `Set.member` kept then contentsSourceCRC32 fullContents else Nothing
            , contentsSourceMD5   = if FieldSourceMD5   `Set.member` kept then contentsSourceMD5   fullContents else Nothing
            , contentsSourceSHA1  = if FieldSourceSHA1  `Set.member` kept then contentsSourceSHA1  fullContents else Nothing
            , contentsDestinationSize    = if FieldDestinationSize    `Set.member` kept then contentsDestinationSize    fullContents else Nothing
            , contentsValidation  = if FieldValidation  `Set.member` kept then contentsValidation  fullContents else Nothing
            , contentsUndoData    = if FieldUndoData    `Set.member` kept then contentsUndoData    fullContents else Nothing
            , contentsTruncation  = if FieldTruncation  `Set.member` kept then contentsTruncation  fullContents else Nothing
            , contentsEBPMetadata = if FieldEBPMeta     `Set.member` kept then contentsEBPMetadata fullContents else Nothing
            , contentsRomType     = if FieldRomType     `Set.member` kept then contentsRomType     fullContents else Nothing
            , contentsImageType   = if FieldImageType   `Set.member` kept then contentsImageType   fullContents else Nothing
            }
          droppedNotes = filter ("note: dropping" `isPrefixOf`) (map (Text.unpack . renderSlapAdvisory) (conversionNotes trimmed format contract noMetadataRequested))
      in droppedNotes === []
  | format <- directFormats
  ]

-- | NINJA1 no longer requires hashes (spec allows zero) -- empty contents must succeed.
prop_ninja1AcceptsEmpty :: Property
prop_ninja1AcceptsEmpty =
  property $ isRight (canConvert (emptyContents []) (directConversionContract CreateNINJA1 OmitUndoData OmitVerification))

-- | APS-N64 requires dest size -- empty contents must fail.
prop_apsn64RejectsEmpty :: Property
prop_apsn64RejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (directConversionContract CreateAPSN64 OmitUndoData OmitVerification))

-- | PPF3 with undo requires undo data -- empty contents must fail.
prop_ppf3UndoRejectsEmpty :: Property
prop_ppf3UndoRejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (directConversionContract CreatePPF3 IncludeUndoData OmitVerification))

-- | PPF3 with validation requires validation block -- empty contents must fail.
prop_ppf3ValidateRejectsEmpty :: Property
prop_ppf3ValidateRejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (directConversionContract CreatePPF3 OmitUndoData IncludeVerification))

-- | Direct conversion to IPS must reject a record at the EOF sentinel offset.
prop_ipsSentinelDirect :: Property
prop_ipsSentinelDirect =
  let patchContent = emptyContents [Hunk (Offset 0x454F46) (ByteString.pack [0xFF])]
  in property $
       assertSentinelUnfixable LabelIPS (SentinelOffset (Offset 0x454F46))
         (convertDirect patchContent (CreateDirect CreateIPS) noMetadataRequested noConstraintsRequested noDialectsRequested)

-- | Direct conversion to IPS32 must reject a record at the EEOF sentinel offset.
prop_ips32SentinelDirect :: Property
prop_ips32SentinelDirect =
  let patchContent = emptyContents [Hunk (Offset 0x45454F46) (ByteString.pack [0xFF])]
  in property $
       assertSentinelUnfixable LabelIPS32 (SentinelOffset (Offset 0x45454F46))
         (convertDirect patchContent (CreateDirect CreateIPS32) noMetadataRequested noConstraintsRequested noDialectsRequested)

-- | A hunk that doesn't start at the sentinel but produces a split fragment
-- at the sentinel offset must be rejected.  Splitting at 0xFFFF turns a hunk
-- at 0x444F47 into chunks at 0x444F47 and 0x454F46 (the EOF sentinel).
-- | A single hunk longer than 0xFFFF whose split lands a record
-- boundary exactly on the sentinel: the preceding chunk covers
-- sentinel-1, so the byte the output must hold there is a record's
-- own payload byte, not a source byte. Source-less convert reads it
-- from that chunk and resolves the collision correctly — where it
-- once refused for want of a source byte it never needed. The
-- converted patch applies to reproduce the hunk's writes.
prop_ipsSentinelSplitDirect :: Property
prop_ipsSentinelSplitDirect =
  let sentinel     = 0x454F46
      startOffset  = sentinel - 0xFFFF   -- 0x444F47: a 0xFFFF split boundary lands on the sentinel
      payload      = ByteString.replicate 0x10000 0xFF  -- > 0xFFFF, forces the split
      patchContent = emptyContents [Hunk (Offset (fromIntegral startOffset)) payload]
      source       = ByteString.replicate (startOffset + 0x10000) 0x00
      expected     = ByteString.replicate startOffset 0x00 <> payload
  in case convertDirect patchContent (CreateDirect CreateIPS)
                        noMetadataRequested noConstraintsRequested noDialectsRequested of
       Left slapError ->
         counterexample ("convert should succeed: " ++ Text.unpack (renderSlapError slapError))
           (property False)
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError ->
           counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) (property False)
         Right (Parsed (IPSParseCleanIPS ipsPatch) _) ->
           case IPS.applyIPS (InputFileContents source) ipsPatch of
             Right outcome ->
               OutputFileContents expected === outcomeValue outcome
             Left slapError ->
               counterexample ("apply: " ++ Text.unpack (renderSlapError slapError)) (property False)
         Right _ ->
           counterexample "expected a clean StandardIPS parse" (property False)

-- | The same resolution at IPS32's sentinel (0x45454F46, ~1.16 GB):
-- the collision now resolves instead of being refused. The round-trip
-- itself is proven by the StandardIPS case above — identical logic,
-- only the sentinel offset differs — since applying at the IPS32
-- sentinel would mean materialising a gigabyte-scale output buffer.
prop_ips32SentinelSplitDirect :: Property
prop_ips32SentinelSplitDirect =
  let startOffset  = 0x45454F46 - 0xFFFF
      payload      = ByteString.replicate 0x10000 0xFF
      patchContent = emptyContents [Hunk (Offset startOffset) payload]
  in case convertDirect patchContent (CreateDirect CreateIPS32)
                        noMetadataRequested noConstraintsRequested noDialectsRequested of
       Left slapError ->
         counterexample ("convert should succeed: " ++ Text.unpack (renderSlapError slapError))
           (property False)
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError ->
           counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) (property False)
         Right (Parsed (IPSParseCleanIPS _) _) -> property True
         Right _ -> counterexample "expected a clean IPS32 parse" (property False)

-- | A record at a negative offset — as a parsed PPF3 patch can carry,
-- PPF3's wire offset being a signed @int64@ (PPF3.txt), so a high-bit
-- value decodes to a negative 'Offset' — must be refused on convert to
-- a bounded target, not 'fromIntegral'-wrapped into a large unsigned
-- wire offset that silently misplaces the write. Apply already rejects
-- a negative offset ('ApplyNegativeRecordOffset'); the narrow boundary
-- now does too, on the convert path that never applies.
prop_ipsNegativeOffsetConvertRefused :: Property
prop_ipsNegativeOffsetConvertRefused =
  let patchContent = emptyContents [Hunk (Offset (-1)) (ByteString.singleton 0x41)]
  in property $
       case convertDirect patchContent (CreateDirect CreateIPS)
                          noMetadataRequested noConstraintsRequested noDialectsRequested of
         Left (NarrowingError (NegativeOffset LabelIPS _)) -> property True
         Left other ->
           counterexample ("expected NarrowingError NegativeOffset, got: "
                            ++ Text.unpack (renderSlapError other)) (property False)
         Right _ ->
           counterexample "expected refusal; a negative offset was silently encoded"
             (property False)

-- | Assert a 'convertDirect' result is 'Left' 'SentinelCollisionUnfixable'
-- with the expected label and sentinel offset. 'CreateResult' has no
-- 'Eq' instance, so the check pattern-matches on the expected error shape
-- rather than comparing the whole result for equality.
assertSentinelUnfixable
  :: FormatLabel
  -> SentinelOffset
  -> Either SlapError CreateResult
  -> Property
assertSentinelUnfixable expectedLabel expectedSentinel result = case result of
  Left (SentinelCollisionUnfixable actualLabel actualSentinel) ->
    (actualLabel, actualSentinel) === (expectedLabel, expectedSentinel)
  Left other ->
    counterexample ("unexpected error: " ++ Text.unpack (renderSlapError other)) (property False)
  Right _ ->
    counterexample "expected SentinelCollisionUnfixable, got successful conversion"
      (property False)

-- | Create path (with source bytes) must handle the sentinel offset correctly.
prop_ipsSentinelWithSource :: Property
prop_ipsSentinelWithSource =
  let eofOffset = 0x454F46
      source = ByteString.replicate (eofOffset + 1) 0
      target = ByteString.replicate eofOffset 0 <> ByteString.pack [0xFF]
  in case createPatch (CreateDirect CreateIPS) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
       Left slapError -> counterexample ("create should succeed: " ++ Text.unpack (renderSlapError slapError)) $ property False
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
         Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
           fmap outcomeValue (IPS.applyIPS (InputFileContents source) ipsPatch)
             === Right (OutputFileContents target)
         Right (Parsed (IPSParseCleanEBP _ebpPatch) _parseWarnings) ->
           counterexample "test fixture unexpectedly EBP" $ property False
         Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
           counterexample "round-tripped IPS unexpectedly truncated" $ property False
