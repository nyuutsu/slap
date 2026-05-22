-- | Fuzz-style robustness: truncate a valid patch at a random offset
-- and verify the parser returns a structured result (Left or Right)
-- rather than crashing.
--
-- Every format that supports create is tested against patches that
-- slap itself produces. Consume-only formats (VCDIFF, BSDiff, XDelta1)
-- are tested against known-good real-world patch files on disk.
module Props.Truncation (truncationTests) where

import qualified Slap.BPS.Parse as BPS
import Slap.BPS.Types (BPSMetadata(..))
import qualified Slap.IPS.Parse as IPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.PMSR.Parse as PMSR
import qualified Slap.NINJA1.Parse as NINJA1
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Parse as DPS
import qualified Slap.NINJA2.Parse as NINJA2
import qualified Slap.APSN64.Parse as APSN64
import qualified Slap.APSGBA.Parse as APSGBA
import qualified Slap.GDIFF.Parse as GDIFF
import qualified Slap.PPF3.Parse as PPF3
import qualified Slap.VCDIFF.Parse as VCDIFF
import qualified Slap.BSDiff.Parse as BSDiff
import qualified Slap.Text as SlapText
import qualified Data.Text as Text
import qualified Slap.XDelta1.Parse as XDelta1

import Slap.Status (CreateResult(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Convert (DirectCreate(..), CreateFormat(..), noMetadataRequested, noConstraintsRequested, noDialectsRequested)
import Slap.Create (createBPS, createUPS, createDPS, createNINJA2,
                    createAPSGBA, createGDIFF, createPatch)

import qualified Data.ByteString as ByteString
import Test.Tasty
import Test.Tasty.QuickCheck

import Props.Helpers

truncationTests :: TestTree
truncationTests = testGroup "Truncation"
  [ testProperty "BPS"     prop_bpsTrunc
  , testProperty "IPS"     prop_ipsTrunc
  , testProperty "IPS32"   prop_ips32Trunc
  , testProperty "EBP"     prop_ebpTrunc
  , testProperty "UPS"     prop_upsTrunc
  , testProperty "PPF3"    prop_ppf3Trunc
  , testProperty "PMSR"    prop_pmsrTrunc
  , testProperty "NINJA1"  prop_ninja1Trunc
  , testProperty "DPS"     prop_dpsTrunc
  , testProperty "NINJA2"  prop_ninja2Trunc
  , testProperty "APS-N64" prop_apsN64Trunc
  , testProperty "APS-GBA" prop_apsGbaTrunc
  , testProperty "GDIFF"   prop_gdiffTrunc
  , testProperty "VCDIFF"  prop_vcdiffTrunc
  , testProperty "BSDiff"  prop_bsdiffTrunc
  , testProperty "XDelta1" prop_xdelta1Trunc
  ]

prop_bpsTrunc :: Property
prop_bpsTrunc = forAll genPair $ \(source, target) ->
  case createBPS (InputFileContents source) (OutputFileContents target) (BPSMetadata ByteString.empty) of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated BPS.parseBPS patch

prop_ipsTrunc :: Property
prop_ipsTrunc = forAll genPair $ \(source, target) ->
  case createPatch (CreateDirect CreateIPS) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated IPS.parseIPS patch

prop_ips32Trunc :: Property
prop_ips32Trunc = forAll genPair $ \(source, target) ->
  case createPatch (CreateDirect CreateIPS32) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated IPS.parseIPS patch

prop_ebpTrunc :: Property
prop_ebpTrunc = forAll genPair $ \(source, target) ->
  case createPatch (CreateDirect CreateEBP) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated IPS.parseIPS patch

prop_upsTrunc :: Property
prop_upsTrunc = forAll genPair $ \(source, target) ->
  case createUPS (InputFileContents source) (OutputFileContents target) of
    Left _createError -> property True
    Right (CreateResult patch _) -> truncated UPS.parseUPS patch

prop_ppf3Trunc :: Property
prop_ppf3Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreatePPF3) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated PPF3.parsePPF3 patch

prop_pmsrTrunc :: Property
prop_pmsrTrunc = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreatePMSR) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated PMSR.parsePMSR patch

prop_ninja1Trunc :: Property
prop_ninja1Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateNINJA1) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated NINJA1.parseNINJA1 patch

prop_dpsTrunc :: Property
prop_dpsTrunc = forAll genPairNoShrink $ \(source, target) ->
  case createDPS (InputFileContents source) (OutputFileContents target)
         (DPS.DPSCreateMetadata
            { DPS.dpsCreateMetadataName    = SlapText.EncodedText SlapText.EncodingLocale Text.empty
            , DPS.dpsCreateMetadataAuthor  = SlapText.EncodedText SlapText.EncodingLocale Text.empty
            , DPS.dpsCreateMetadataVersion = SlapText.EncodedText SlapText.EncodingLocale Text.empty
            })
         DPS.DPSStable of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated DPS.parseDPS patch

prop_ninja2Trunc :: Property
prop_ninja2Trunc = forAll genPair $ \(source, target) ->
  case createNINJA2 (InputFileContents source) (OutputFileContents target) emptyNINJA2Metadata of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated NINJA2.parseNINJA2 patch

prop_apsN64Trunc :: Property
prop_apsN64Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateAPSN64) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated APSN64.parseAPSN64 patch

prop_apsGbaTrunc :: Property
prop_apsGbaTrunc = forAll genPair $ \(source, target) ->
  case createAPSGBA (InputFileContents source) (OutputFileContents target) of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated APSGBA.parseAPSGBA patch

prop_gdiffTrunc :: Property
prop_gdiffTrunc = forAll genPair $ \(source, target) ->
  case createGDIFF (InputFileContents source) (OutputFileContents target) of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated GDIFF.parseGDIFF patch

-- Consume-only formats: truncation on real test data

prop_vcdiffTrunc :: Property
prop_vcdiffTrunc = truncatedFile VCDIFF.parseVCDIFF "test/data/dm4y/patch.vcdiff"

prop_bsdiffTrunc :: Property
prop_bsdiffTrunc = truncatedFile BSDiff.parseBSDiff "test/data/dm4y/patch.bsdiff"

prop_xdelta1Trunc :: Property
prop_xdelta1Trunc = truncatedFile XDelta1.parseXDelta1 "test/data/dm4y/patch.xdelta1"
