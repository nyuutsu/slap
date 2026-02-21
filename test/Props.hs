module Main (main) where

import qualified Patch.BPS as BPS
import qualified Patch.IPS as IPS
import qualified Patch.UPS as UPS
import qualified Patch.PMSR as PMSR
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.DPS as DPS
import qualified Patch.RUP as RUP
import qualified Patch.APS as APS
import qualified Patch.GDIFF as GDIFF
import qualified Patch.PPF.Create as PPF
import qualified Patch.PPF.Parse as PPF
import qualified Patch.PPF.Apply as PPF
import qualified Patch.VCDIFF as VCDIFF
import qualified Patch.BSDiff as BSDiff
import qualified Patch.XDelta1 as XDelta1

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import System.Directory (getTemporaryDirectory, removeFile)
import System.IO (hClose, openBinaryTempFile)
import Test.Tasty
import Test.Tasty.QuickCheck

main :: IO ()
main = defaultMain $ testGroup "Properties"
  [ testGroup "BPS"
      [ testProperty "round-trip" prop_bps
      , testProperty "parse-truncated" prop_bpsTrunc ]
  , testGroup "IPS"
      [ testProperty "round-trip" prop_ips
      , testProperty "parse-truncated" prop_ipsTrunc ]
  , testGroup "IPS32"
      [ testProperty "round-trip" prop_ips32
      , testProperty "parse-truncated" prop_ips32Trunc ]
  , testGroup "EBP"
      [ testProperty "round-trip" prop_ebp
      , testProperty "parse-truncated" prop_ebpTrunc ]
  , testGroup "UPS"
      [ testProperty "round-trip" prop_ups
      , testProperty "parse-truncated" prop_upsTrunc ]
  , testGroup "PPF3"
      [ testProperty "round-trip" prop_ppf3
      , testProperty "parse-truncated" prop_ppf3Trunc ]
  , testGroup "PMSR"
      [ testProperty "round-trip" prop_pmsr
      , testProperty "parse-truncated" prop_pmsrTrunc ]
  , testGroup "NINJA1"
      [ testProperty "round-trip" prop_ninja1
      , testProperty "parse-truncated" prop_ninja1Trunc ]
  , testGroup "DPS"
      [ testProperty "round-trip" prop_dps
      , testProperty "parse-truncated" prop_dpsTrunc ]
  , testGroup "RUP"
      [ testProperty "round-trip" prop_rup
      , testProperty "parse-truncated" prop_rupTrunc ]
  , testGroup "APS-N64"
      [ testProperty "round-trip" prop_apsN64
      , testProperty "parse-truncated" prop_apsN64Trunc ]
  , testGroup "APS-GBA"
      [ testProperty "round-trip" prop_apsGba
      , testProperty "parse-truncated" prop_apsGbaTrunc ]
  , testGroup "GDIFF"
      [ testProperty "round-trip" prop_gdiff
      , testProperty "parse-truncated" prop_gdiffTrunc ]
  , testGroup "VCDIFF"
      [ testProperty "parse-truncated" prop_vcdiffTrunc ]
  , testGroup "BSDiff"
      [ testProperty "parse-truncated" prop_bsdiffTrunc ]
  , testGroup "XDelta1"
      [ testProperty "parse-truncated" prop_xdelta1Trunc ]
  ]

----------------------------------------------------------------------------
-- Generators
----------------------------------------------------------------------------

-- | Arbitrary ByteString up to ~64 KB, biased toward small sizes and edge cases.
genBS :: Gen ByteString
genBS = frequency
  [ (1, pure BS.empty)
  , (2, BS.singleton <$> arbitrary)
  , (5, sized $ \n -> do
      len <- choose (0, min (n * 64) 65536)
      BS.pack <$> vectorOf len arbitrary)
  ]

-- | Arbitrary (source, target) pair with no size constraints.
genPair :: Gen (ByteString, ByteString)
genPair = (,) <$> genBS <*> genBS

-- | (source, target) where len(target) >= len(source).
-- Pure overlay formats that lack truncation support can only grow or stay same-size.
-- Affected: PPF3, PMSR, NINJA1, DPS, APS-N64.
genPairNoShrink :: Gen (ByteString, ByteString)
genPairNoShrink = do
  a <- genBS
  b <- genBS
  pure $ if BS.length a <= BS.length b then (a, b) else (b, a)

-- | Apply an overlay patch via temp file, return result bytes.
applyViaFile :: (p -> FilePath -> IO a) -> p -> ByteString -> IO ByteString
applyViaFile applyFn patch source = do
  dir <- getTemporaryDirectory
  (tmp, h) <- openBinaryTempFile dir "slap-prop"
  BS.hPut h source
  hClose h
  _ <- applyFn patch tmp
  result <- BS.readFile tmp
  removeFile tmp
  pure result

----------------------------------------------------------------------------
-- Delta formats: handle any size combination
----------------------------------------------------------------------------

prop_bps :: Property
prop_bps = forAll genPair $ \(src, tgt) ->
  let patch = BPS.createBPS src tgt
  in case BPS.parseBPS patch >>= \p -> BPS.applyBPS p src of
       Left err     -> counterexample err $ property False
       Right result -> result === tgt

prop_ups :: Property
prop_ups = forAll genPair $ \(src, tgt) ->
  let patch = UPS.createUPS src tgt
  in case UPS.parseUPS patch of
       Left err -> counterexample err $ property False
       Right p  -> UPS.applyUPS p src === tgt

prop_ips :: Property
prop_ips = forAll genPair $ \(src, tgt) ->
  case IPS.createIPS src tgt of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left err -> counterexample ("parse: " ++ err) $ property False
      Right p  -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS p src
        pure $ result === tgt

prop_gdiff :: Property
prop_gdiff = forAll genPair $ \(src, tgt) ->
  let patch = GDIFF.createGDIFF src tgt
  in case GDIFF.parseGDIFF patch >>= \p -> GDIFF.applyGDIFF p src of
       Left err     -> counterexample err $ property False
       Right result -> result === tgt

prop_apsGba :: Property
prop_apsGba = forAll genPair $ \(src, tgt) ->
  let patch = APS.createAPSGBA src tgt
  in case APS.parseAPS patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile APS.applyAPS p src
         pure $ result === tgt

----------------------------------------------------------------------------
-- Formats with truncation support (any size combination)
----------------------------------------------------------------------------

prop_ips32 :: Property
prop_ips32 = forAll genPair $ \(src, tgt) ->
  case IPS.createIPS32 src tgt of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left err -> counterexample ("parse: " ++ err) $ property False
      Right p  -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS p src
        pure $ result === tgt

prop_ebp :: Property
prop_ebp = forAll genPair $ \(src, tgt) ->
  case IPS.createEBP src tgt "" of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left err -> counterexample ("parse: " ++ err) $ property False
      Right p  -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS p src
        pure $ result === tgt

-- Pure overlays: no truncation, target must be >= source
prop_ppf3 :: Property
prop_ppf3 = forAll genPairNoShrink $ \(src, tgt) ->
  let patch = PPF.createPatchPure src tgt "" False False
  in case PPF.parsePatch patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile PPF.applyPatch p src
         pure $ result === tgt

prop_pmsr :: Property
prop_pmsr = forAll genPairNoShrink $ \(src, tgt) ->
  let patch = PMSR.createPMSR src tgt
  in case PMSR.parsePMSR patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile PMSR.applyPMSR p src
         pure $ result === tgt

prop_ninja1 :: Property
prop_ninja1 = forAll genPairNoShrink $ \(src, tgt) ->
  let patch = NINJA1.createNINJA1 src tgt
  in case NINJA1.parseNINJA1 patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile NINJA1.applyNINJA1 p src
         pure $ result === tgt

-- DPS: overlay with extension, but no truncation
prop_dps :: Property
prop_dps = forAll genPairNoShrink $ \(src, tgt) ->
  let patch = DPS.createDPS src tgt
  in case DPS.parseDPS patch >>= \p -> DPS.applyDPS p src of
       Left err     -> counterexample err $ property False
       Right result -> result === tgt

prop_rup :: Property
prop_rup = forAll genPair $ \(src, tgt) ->
  let patch = RUP.createRUP src tgt
  in case RUP.parseRUP patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile RUP.applyRUP p src
         pure $ result === tgt

-- APS-N64: pure overlay, no truncation
prop_apsN64 :: Property
prop_apsN64 = forAll genPairNoShrink $ \(src, tgt) ->
  let patch = APS.createAPSN64 src tgt
  in case APS.parseAPS patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile APS.applyAPS p src
         pure $ result === tgt

----------------------------------------------------------------------------
-- Parse-truncated: truncate valid patches to random lengths, verify no crash
----------------------------------------------------------------------------

-- | Truncate a patch to a random length and verify parse returns Left or Right
-- (never crashes).  Parsers with StrictData build results eagerly, so
-- evaluating the Either constructor is sufficient to trigger any index errors.
truncated :: (ByteString -> Either String a) -> ByteString -> Property
truncated parse patch =
  forAll (choose (0, BS.length patch - 1)) $ \len ->
    case parse (BS.take len patch) of
      Left _  -> property True
      Right _ -> property True

prop_bpsTrunc :: Property
prop_bpsTrunc = forAll genPair $ \(src, tgt) ->
  truncated BPS.parseBPS (BPS.createBPS src tgt)

prop_ipsTrunc :: Property
prop_ipsTrunc = forAll genPair $ \(src, tgt) ->
  case IPS.createIPS src tgt of
    Left _ -> discard
    Right patch -> truncated IPS.parseIPS patch

prop_ips32Trunc :: Property
prop_ips32Trunc = forAll genPair $ \(src, tgt) ->
  case IPS.createIPS32 src tgt of
    Left _ -> discard
    Right patch -> truncated IPS.parseIPS patch

prop_ebpTrunc :: Property
prop_ebpTrunc = forAll genPair $ \(src, tgt) ->
  case IPS.createEBP src tgt "" of
    Left _ -> discard
    Right patch -> truncated IPS.parseIPS patch

prop_upsTrunc :: Property
prop_upsTrunc = forAll genPair $ \(src, tgt) ->
  truncated UPS.parseUPS (UPS.createUPS src tgt)

prop_ppf3Trunc :: Property
prop_ppf3Trunc = forAll genPairNoShrink $ \(src, tgt) ->
  truncated PPF.parsePatch (PPF.createPatchPure src tgt "" False False)

prop_pmsrTrunc :: Property
prop_pmsrTrunc = forAll genPairNoShrink $ \(src, tgt) ->
  truncated PMSR.parsePMSR (PMSR.createPMSR src tgt)

prop_ninja1Trunc :: Property
prop_ninja1Trunc = forAll genPairNoShrink $ \(src, tgt) ->
  truncated NINJA1.parseNINJA1 (NINJA1.createNINJA1 src tgt)

prop_dpsTrunc :: Property
prop_dpsTrunc = forAll genPairNoShrink $ \(src, tgt) ->
  truncated DPS.parseDPS (DPS.createDPS src tgt)

prop_rupTrunc :: Property
prop_rupTrunc = forAll genPair $ \(src, tgt) ->
  truncated RUP.parseRUP (RUP.createRUP src tgt)

prop_apsN64Trunc :: Property
prop_apsN64Trunc = forAll genPairNoShrink $ \(src, tgt) ->
  truncated APS.parseAPS (APS.createAPSN64 src tgt)

prop_apsGbaTrunc :: Property
prop_apsGbaTrunc = forAll genPair $ \(src, tgt) ->
  truncated APS.parseAPS (APS.createAPSGBA src tgt)

prop_gdiffTrunc :: Property
prop_gdiffTrunc = forAll genPair $ \(src, tgt) ->
  truncated GDIFF.parseGDIFF (GDIFF.createGDIFF src tgt)

----------------------------------------------------------------------------
-- Consume-only formats: truncation on real test data
----------------------------------------------------------------------------

-- | Truncate a real patch file from disk to random lengths.
-- These formats have no create function; use known-good patches instead.
truncatedFile :: (ByteString -> Either String a) -> FilePath -> Property
truncatedFile parse path = ioProperty $ do
  patch <- BS.readFile path
  pure $ forAll (choose (0, BS.length patch - 1)) $ \len ->
    case parse (BS.take len patch) of
      Left _  -> property True
      Right _ -> property True

prop_vcdiffTrunc :: Property
prop_vcdiffTrunc = truncatedFile VCDIFF.parseVCDIFF "test/data/dm4k/patch.vcdiff"

prop_bsdiffTrunc :: Property
prop_bsdiffTrunc = truncatedFile BSDiff.parseBSDiff "test/data/dm4k/patch.bsdiff"

prop_xdelta1Trunc :: Property
prop_xdelta1Trunc = truncatedFile XDelta1.parseXDelta1 "test/data/dm4k/patch.xdelta1"
