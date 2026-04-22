-- | Tests for the conversion contract system.
--
-- 'canConvert' decides whether a 'PatchContents' bundle carries
-- everything a target 'FormatSpecification' requires. 'conversionNotes'
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

import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.Error (CreateResult(..), SlapError(..), renderSlapError, renderSlapWarning)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), FileSize(..), Hunk(..), UndoHunk(..),
                     SentinelOffset(..))
import Slap.Convert (PatchContents(..), DirectCreate(..), CreateFormat(..),
                      FormatSpecification(..), defaultMeta, formatSpecification,
                      emptyContents, canConvert, convertDirect, conversionNotes)
import Slap.Create (createFromMemory)
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
  , contentsUndoData    = Just [UndoHunk (Offset 0) (ByteString.pack [0x00]) (ByteString.pack [0xFF])]
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

-- | canConvert succeeds for every direct format when all fields are present.
prop_canConvertFull :: Property
prop_canConvertFull = conjoin
  [ counterexample (show format) $
      canConvert fullContents (formatSpecification format True True) === Right ()
  | format <- directFormats
  ]

-- | No dropped-field notes when provides exactly matches required + accepted.
prop_noSurplusNoNotes :: Property
prop_noSurplusNoNotes = conjoin
  [ counterexample (show format) $
      let spec = formatSpecification format True True
          kept = specificationRequired spec `Set.union` specificationAccepted spec
          trimmed = fullContents
            { contentsDescription = if FDescription `Set.member` kept then contentsDescription fullContents else Nothing
            , contentsSourceCRC32 = if FSourceCRC32 `Set.member` kept then contentsSourceCRC32 fullContents else Nothing
            , contentsSourceMD5   = if FSourceMD5   `Set.member` kept then contentsSourceMD5   fullContents else Nothing
            , contentsSourceSHA1  = if FSourceSHA1  `Set.member` kept then contentsSourceSHA1  fullContents else Nothing
            , contentsDestinationSize    = if FDestinationSize    `Set.member` kept then contentsDestinationSize    fullContents else Nothing
            , contentsValidation  = if FValidation  `Set.member` kept then contentsValidation  fullContents else Nothing
            , contentsUndoData    = if FUndoData    `Set.member` kept then contentsUndoData    fullContents else Nothing
            , contentsTruncation  = if FTruncation  `Set.member` kept then contentsTruncation  fullContents else Nothing
            , contentsEBPMeta     = if FEBPMeta     `Set.member` kept then contentsEBPMeta     fullContents else Nothing
            , contentsRomType     = if FRomType     `Set.member` kept then contentsRomType     fullContents else Nothing
            , contentsImageType   = if FImageType   `Set.member` kept then contentsImageType   fullContents else Nothing
            }
          droppedNotes = filter ("note: dropping" `isPrefixOf`) (map renderSlapWarning (conversionNotes trimmed format spec defaultMeta))
      in droppedNotes === []
  | format <- directFormats
  ]

-- | NINJA1 no longer requires hashes (spec allows zero) -- empty contents must succeed.
prop_ninja1AcceptsEmpty :: Property
prop_ninja1AcceptsEmpty =
  property $ isRight (canConvert (emptyContents []) (formatSpecification CreateNINJA1 False False))

-- | APS-N64 requires dest size -- empty contents must fail.
prop_apsn64RejectsEmpty :: Property
prop_apsn64RejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpecification CreateAPSN64 False False))

-- | PPF3 with undo requires undo data -- empty contents must fail.
prop_ppf3UndoRejectsEmpty :: Property
prop_ppf3UndoRejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpecification CreatePPF3 True False))

-- | PPF3 with validation requires validation block -- empty contents must fail.
prop_ppf3ValidateRejectsEmpty :: Property
prop_ppf3ValidateRejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpecification CreatePPF3 False True))

-- | Direct conversion to IPS must reject a record at the EOF sentinel offset.
prop_ipsSentinelDirect :: Property
prop_ipsSentinelDirect =
  let patchContent = emptyContents [Hunk (Offset 0x454F46) (ByteString.pack [0xFF])]
  in property $
       assertSentinelUnfixable LabelIPS (SentinelOffset (Offset 0x454F46))
         (convertDirect patchContent (CreateDirect CreateIPS) defaultMeta)

-- | Direct conversion to IPS32 must reject a record at the EEOF sentinel offset.
prop_ips32SentinelDirect :: Property
prop_ips32SentinelDirect =
  let patchContent = emptyContents [Hunk (Offset 0x45454F46) (ByteString.pack [0xFF])]
  in property $
       assertSentinelUnfixable LabelIPS32 (SentinelOffset (Offset 0x45454F46))
         (convertDirect patchContent (CreateDirect CreateIPS32) defaultMeta)

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
         (convertDirect patchContent (CreateDirect CreateIPS) defaultMeta)

-- | Same as above for IPS32: split fragment at EEOF sentinel 0x45454F46.
prop_ips32SentinelSplitDirect :: Property
prop_ips32SentinelSplitDirect =
  let startOffset = 0x45454F46 - 0xFFFF
      payload = ByteString.replicate 0x10000 0xFF
      patchContent = emptyContents [Hunk (Offset startOffset) payload]
  in property $
       assertSentinelUnfixable LabelIPS32 (SentinelOffset (Offset 0x45454F46))
         (convertDirect patchContent (CreateDirect CreateIPS32) defaultMeta)

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
  in case createFromMemory (CreateDirect CreateIPS) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
       Left slapError -> counterexample ("create should succeed: " ++ renderSlapError slapError) $ property False
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
         Right (Left ipsPatch) ->
           IPS.applyIPS (SourceFileContents source) ipsPatch === Right (TargetFileContents target)
         Right (Right _ebpPatch) ->
           counterexample "test fixture unexpectedly EBP" $ property False
