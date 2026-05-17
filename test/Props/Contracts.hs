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
import Slap.Create (createPatch)
import Slap.PatchField (PatchField(..))
import Slap.PlatformType (PlatformType(..))

import qualified Data.ByteString as ByteString
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
  ]

-- | Direct formats that go through buildContents -> encodeDirect.
directFormats :: [DirectCreate]
directFormats =
  [CreateIPS, CreateIPS32, CreateEBP, CreatePPF3, CreateNINJA1, CreatePMSR, CreatePCHTXT, CreateAPSN64]

-- | PatchContents with every field populated.
fullContents :: PatchContents
fullContents = PatchContents
  { contentsRecords     = [Hunk (Offset 0) (ByteString.pack [0xFF])]
  , contentsDescription = Just (ByteString.pack [0x74, 0x65, 0x73, 0x74])
  , contentsSourceCRC32 = Just (CRC32 0xDEADBEEF)
  , contentsSourceMD5   = Just (MD5Hash (ByteString.replicate 16 0xAA))
  , contentsSourceSHA1  = Just (SHA1Hash (ByteString.replicate 20 0xBB))
  , contentsDestinationSize    = Just (FileSize 1024)
  , contentsValidation  = Just (ByteString.replicate 1024 0)
  , contentsUndoData    = Just [splitUndoHunkFromParsed (Offset 0) (ByteString.pack [0x00]) (ByteString.pack [0xFF])]
  , contentsTruncation  = Just (FileSize 512)
  , contentsEBPMeta     = Just (ByteString.pack [0x7B, 0x7D])
  , contentsRomType     = Just PlatformRaw
  , contentsImageType   = Nothing
  , contentsFileIdDiz   = Nothing
  , contentsPCHTXTBlocks = Nothing
  , contentsNINJA1Compressed = Nothing
  , contentsMetadata = Nothing
  , contentsPatchEncoding = Nothing
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
            , contentsEBPMeta     = if FieldEBPMeta     `Set.member` kept then contentsEBPMeta     fullContents else Nothing
            , contentsRomType     = if FieldRomType     `Set.member` kept then contentsRomType     fullContents else Nothing
            , contentsImageType   = if FieldImageType   `Set.member` kept then contentsImageType   fullContents else Nothing
            }
          droppedNotes = filter ("note: dropping" `isPrefixOf`) (map renderSlapAdvisory (conversionNotes trimmed format contract noMetadataRequested))
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
prop_ipsSentinelSplitDirect :: Property
prop_ipsSentinelSplitDirect =
  let startOffset = 0x454F46 - 0xFFFF  -- 0x444F47: split fragment lands on sentinel
      payload = ByteString.replicate 0x10000 0xFF  -- > 0xFFFF, forces split
      patchContent = emptyContents [Hunk (Offset startOffset) payload]
  in property $
       assertSentinelUnfixable LabelIPS (SentinelOffset (Offset 0x454F46))
         (convertDirect patchContent (CreateDirect CreateIPS) noMetadataRequested noConstraintsRequested noDialectsRequested)

-- | Same as above for IPS32: split fragment at EEOF sentinel 0x45454F46.
prop_ips32SentinelSplitDirect :: Property
prop_ips32SentinelSplitDirect =
  let startOffset = 0x45454F46 - 0xFFFF
      payload = ByteString.replicate 0x10000 0xFF
      patchContent = emptyContents [Hunk (Offset startOffset) payload]
  in property $
       assertSentinelUnfixable LabelIPS32 (SentinelOffset (Offset 0x45454F46))
         (convertDirect patchContent (CreateDirect CreateIPS32) noMetadataRequested noConstraintsRequested noDialectsRequested)

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
    counterexample ("unexpected error: " ++ renderSlapError other) (property False)
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
       Left slapError -> counterexample ("create should succeed: " ++ renderSlapError slapError) $ property False
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
         Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
           fmap outcomeValue (IPS.applyIPS (InputFileContents source) ipsPatch)
             === Right (OutputFileContents target)
         Right (Parsed (IPSParseCleanEBP _ebpPatch) _parseWarnings) ->
           counterexample "test fixture unexpectedly EBP" $ property False
         Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
           counterexample "round-tripped IPS unexpectedly truncated" $ property False
