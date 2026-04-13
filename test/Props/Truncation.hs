-- | Fuzz-style robustness: truncate a valid patch at a random offset
-- and verify the parser returns a structured result (Left or Right)
-- rather than crashing.
--
-- Every format that supports create is tested against patches that
-- slap itself produces. Consume-only formats (VCDIFF, BSDiff, XDelta1)
-- are tested against known-good real-world patch files on disk.
module Props.Truncation (truncationTests) where

import qualified Slap.BPS.Create as BPS
import qualified Slap.BPS.Parse as BPS
import qualified Slap.IPS.Parse as IPS
import qualified Slap.UPS.Create as UPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.PMSR.Parse as PMSR
import qualified Slap.NINJA1.Parse as NINJA1
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Parse as DPS
import qualified Slap.DPS.Create as DPS
import qualified Slap.NINJA2.Parse as NINJA2
import qualified Slap.NINJA2.Create as NINJA2
import qualified Slap.NINJA2.Types as NINJA2
import qualified Slap.APSN64.Parse as APSN64
import qualified Slap.APSGBA.Parse as APSGBA
import qualified Slap.APSGBA.Create as APSGBA
import qualified Slap.GDIFF.Parse as GDIFF
import qualified Slap.GDIFF.Create as GDIFF
import qualified Slap.PPF.Parse as PPF
import qualified Slap.PCHTXT.Parse as PCHTXT
import qualified Slap.VCDIFF.Parse as VCDIFF
import qualified Slap.BSDiff.Parse as BSDiff
import qualified Slap.XDelta1.Parse as XDelta1

import Slap.Error (CreateResult(..))
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))
import Slap.Convert (DirectCreate(..), CreateFormat(..), defaultMeta, createFromMemory)

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
  , testProperty "PCHTXT"  prop_pchtxtTrunc
  , testProperty "VCDIFF"  prop_vcdiffTrunc
  , testProperty "BSDiff"  prop_bsdiffTrunc
  , testProperty "XDelta1" prop_xdelta1Trunc
  ]

prop_bpsTrunc :: Property
prop_bpsTrunc = forAll genPair $ \(source, target) ->
  truncated BPS.parseBPS (BPS.createBPS (SourceFileContents source) (TargetFileContents target) ByteString.empty)

prop_ipsTrunc :: Property
prop_ipsTrunc = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated IPS.parseIPS patch

prop_ips32Trunc :: Property
prop_ips32Trunc = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS32) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated IPS.parseIPS patch

prop_ebpTrunc :: Property
prop_ebpTrunc = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateEBP) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated IPS.parseIPS patch

prop_upsTrunc :: Property
prop_upsTrunc = forAll genPair $ \(source, target) ->
  case UPS.createUPS (SourceFileContents source) (TargetFileContents target) of
    Left _createError -> property True
    Right patch -> truncated UPS.parseUPS patch

prop_ppf3Trunc :: Property
prop_ppf3Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePPF3) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated PPF.parsePatch patch

prop_pmsrTrunc :: Property
prop_pmsrTrunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePMSR) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated PMSR.parsePMSR patch

prop_ninja1Trunc :: Property
prop_ninja1Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateNINJA1) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated NINJA1.parseNINJA1 patch

prop_dpsTrunc :: Property
prop_dpsTrunc = forAll genPairNoShrink $ \(source, target) ->
  truncated DPS.parseDPS (resultBytes (DPS.createDPS (SourceFileContents source) (TargetFileContents target)
    (DPS.DPSMetadata { DPS.dpsMetadataName = "", DPS.dpsMetadataAuthor = "", DPS.dpsMetadataVersion = "" })
    DPS.DPSStable))

prop_ninja2Trunc :: Property
prop_ninja2Trunc = forAll genPair $ \(source, target) ->
  truncated NINJA2.parseNINJA2 (NINJA2.createNINJA2 (SourceFileContents source) (TargetFileContents target) emptyNinja2Info NINJA2.Ninja2Raw NINJA2.PatchEncodingUTF8)

prop_apsN64Trunc :: Property
prop_apsN64Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateAPSN64) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated APSN64.parseAPSN64 patch

prop_apsGbaTrunc :: Property
prop_apsGbaTrunc = forAll genPair $ \(source, target) ->
  truncated APSGBA.parseAPSGBA (APSGBA.createAPSGBA (SourceFileContents source) (TargetFileContents target))

prop_gdiffTrunc :: Property
prop_gdiffTrunc = forAll genPair $ \(source, target) ->
  truncated GDIFF.parseGDIFF (GDIFF.createGDIFF (SourceFileContents source) (TargetFileContents target))

prop_pchtxtTrunc :: Property
prop_pchtxtTrunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePCHTXT) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated PCHTXT.parsePCHTXT patch

-- Consume-only formats: truncation on real test data

prop_vcdiffTrunc :: Property
prop_vcdiffTrunc = truncatedFile VCDIFF.parseVCDIFF "test/data/dm4y/patch.vcdiff"

prop_bsdiffTrunc :: Property
prop_bsdiffTrunc = truncatedFile BSDiff.parseBSDiff "test/data/dm4y/patch.bsdiff"

prop_xdelta1Trunc :: Property
prop_xdelta1Trunc = truncatedFile XDelta1.parseXDelta1 "test/data/dm4y/patch.xdelta1"
