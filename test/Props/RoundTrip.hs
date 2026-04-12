-- | Create-parse-apply round-trip tests for every format that supports
-- creation. The single property every format satisfies:
--
-- > applyFmt (parseFmt (createFmt src tgt)) src == tgt
--
-- Plus a handful of format-specific round-trip-adjacent properties
-- (hash preservation for NINJA1/RUP, patch size bounds for BPS, etc.)
-- that are naturally expressed as extensions of the basic round-trip.
module Props.RoundTrip (roundTripTests) where

import qualified Slap.BPS.Apply as BPS
import qualified Slap.BPS.Create as BPS
import qualified Slap.BPS.Parse as BPS
import qualified Slap.BPS.Types as BPS
import qualified Slap.IPS.Apply as IPS
import qualified Slap.IPS.Parse as IPS
import Slap.IPS.Create (avoidSentinel, optimalIPSRecords)
import Slap.IPS.Types (OffsetWidth(..), EBPPatch(..))
import qualified Slap.UPS.Apply as UPS
import qualified Slap.UPS.Create as UPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.PMSR.Parse as PMSR
import qualified Slap.PMSR.Apply as PMSR
import qualified Slap.NINJA1.Parse as NINJA1
import qualified Slap.NINJA1.Apply as NINJA1
import qualified Slap.NINJA1.Types as NINJA1
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Parse as DPS
import qualified Slap.DPS.Apply as DPS
import qualified Slap.DPS.Create as DPS
import qualified Slap.RUP.Types as RUP
import qualified Slap.RUP.Parse as RUP
import qualified Slap.RUP.Apply as RUP
import qualified Slap.RUP.Create as RUP
import qualified Slap.APSN64.Parse as APSN64
import qualified Slap.APSN64.Apply as APSN64
import qualified Slap.APSGBA.Parse as APSGBA
import qualified Slap.APSGBA.Apply as APSGBA
import qualified Slap.APSGBA.Create as APSGBA
import qualified Slap.GDIFF.Parse as GDIFF
import qualified Slap.GDIFF.Apply as GDIFF
import qualified Slap.GDIFF.Create as GDIFF
import qualified Slap.PPF.Parse as PPF
import qualified Slap.PPF.Apply as PPF
import qualified Slap.PCHTXT.Parse as PCHTXT
import qualified Slap.PCHTXT.Apply as PCHTXT
import qualified Slap.PCHTXT.Types as PCHTXT

import Slap.Binary (md5, sha1, diffHunks)
import Slap.Checksum (MD5Hash(..))
import Slap.Error (CreateResult(..), renderSlapError)
import Slap.Measure (Offset(..), EncodedHunk(..))
import Slap.FFI (rustyCRC32)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.Convert (DirectCreate(..), CreateFormat(..),
                     defaultMeta, createFromMemory)

import qualified Data.ByteString as ByteString
import Test.Tasty
import Test.Tasty.HUnit (testCase, assertEqual)
import Test.Tasty.QuickCheck

import Props.Helpers

roundTripTests :: TestTree
roundTripTests = testGroup "RoundTrip"
  [ testGroup "BPS"
      [ testProperty "round-trip" prop_bps
      , testProperty "block-move" prop_bpsBlockMove
      , testProperty "no-size-regression" prop_bpsNoSizeRegression
      , testProperty "metadata-round-trip" prop_bpsMetadata
      ]
  , testGroup "IPS"
      [ testProperty "round-trip" prop_ips
      , testProperty "eof-collision" prop_ipsEofCollision
      , testProperty "avoidSentinel" prop_avoidSentinel
      , testProperty "dp-not-larger" prop_dpNotLarger
      ]
  , testGroup "IPS32"
      [ testProperty "round-trip" prop_ips32
      , testProperty "dp-not-larger" prop_dpIPS32NotLarger
      ]
  , testGroup "EBP"
      [ testProperty "round-trip" prop_ebp
      ]
  , testGroup "UPS"
      [ testProperty "round-trip" prop_ups
      ]
  , testGroup "PPF3"
      [ testProperty "round-trip" prop_ppf3
      ]
  , testGroup "PMSR"
      [ testProperty "round-trip" prop_pmsr
      ]
  , testGroup "NINJA1"
      [ testProperty "round-trip" prop_ninja1
      , testProperty "hashes" prop_ninja1Hashes
      ]
  , testGroup "DPS"
      [ testProperty "round-trip" prop_dps
      ]
  , testGroup "RUP"
      [ testProperty "round-trip" prop_rup
      , testProperty "hashes" prop_rupHashes
      ]
  , testGroup "APS-N64"
      [ testProperty "round-trip" prop_apsN64
      ]
  , testGroup "APS-GBA"
      [ testProperty "round-trip" prop_apsGba
      ]
  , testGroup "GDIFF"
      [ testProperty "round-trip" prop_gdiff
      ]
  , testGroup "PCHTXT"
      [ testProperty "round-trip" prop_pchtxt
      , testCase "parse-escapes" parsePchtxtEscapes
      , testCase "parse-sphinx" parsePchtxtSphinx
      ]
  ]

----------------------------------------------------------------------------
-- Delta formats: handle any size combination
----------------------------------------------------------------------------

prop_bps :: Property
prop_bps = forAll genPair $ \(source, target) ->
  let patch = BPS.createBPS (SourceFileContents source) (TargetFileContents target) ByteString.empty
  in case BPS.parseBPS patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> BPS.applyBPS parsed (SourceFileContents source) === Right (TargetFileContents target)

prop_bpsMetadata :: Property
prop_bpsMetadata = forAll genPair $ \(source, target) ->
  forAll genByteString $ \meta ->
    let patch = BPS.createBPS (SourceFileContents source) (TargetFileContents target) meta
    in case BPS.parseBPS patch of
         Left slapError -> counterexample (renderSlapError slapError) $ property False
         Right parsed -> BPS.bpsMetadata parsed === meta

prop_ups :: Property
prop_ups = forAll genPair $ \(source, target) ->
  case UPS.createUPS (SourceFileContents source) (TargetFileContents target) of
    Left _createError -> property True
    Right patch ->
      case UPS.parseUPS patch of
        Left parseError ->
          counterexample (renderSlapError parseError) $ property False
        Right parsed ->
          UPS.applyUPS parsed (SourceFileContents source) === Right (TargetFileContents target)

prop_ips :: Property
prop_ips = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Left ipsPatch) ->
        IPS.applyIPS (SourceFileContents source) ipsPatch === Right (TargetFileContents target)
      Right (Right _ebpPatch) ->
        counterexample "test fixture unexpectedly EBP" $ property False

prop_ipsEofCollision :: Property
prop_ipsEofCollision = withNumTests 20 $ forAll genEofPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Left ipsPatch) ->
        IPS.applyIPS (SourceFileContents source) ipsPatch === Right (TargetFileContents target)
      Right (Right _ebpPatch) ->
        counterexample "test fixture unexpectedly EBP" $ property False

prop_avoidSentinel :: Property
prop_avoidSentinel = property $
  let source = ByteString.pack [0, 1, 2, 3, 4, 5, 6, 7]
  in conjoin
    [ -- Record at sentinel is shifted back
      avoidSentinel 5 source [EncodedHunk (Offset 5) (ByteString.pack [0xFF])]
        === [EncodedHunk (Offset 4) (ByteString.pack [4, 0xFF])]
    , -- Record NOT at sentinel is unchanged
      avoidSentinel 5 source [EncodedHunk (Offset 3) (ByteString.pack [0xAA])]
        === [EncodedHunk (Offset 3) (ByteString.pack [0xAA])]
    , -- Source too short: no-op
      avoidSentinel 5 ByteString.empty [EncodedHunk (Offset 5) (ByteString.pack [0xFF])]
        === [EncodedHunk (Offset 5) (ByteString.pack [0xFF])]
    , -- Sentinel at offset 0: can't extend backward, no-op
      avoidSentinel 0 source [EncodedHunk (Offset 0) (ByteString.pack [0xFF])]
        === [EncodedHunk (Offset 0) (ByteString.pack [0xFF])]
    ]

-- | DP patch size must not exceed greedy patch size for IPS (offWidth=3).
prop_dpNotLarger :: Property
prop_dpNotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords =
        optimalIPSRecords Offset24 (SourceFileContents source) (TargetFileContents target)
      greedyRecords = splitMax 0xFFFF (diffHunks source target)
      dynamicProgrammingSize = ipsEncodedSize 3 dynamicProgrammingRecords
      greedySize = ipsEncodedSize 3 greedyRecords
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

-- | DP patch size must not exceed greedy patch size for IPS32 (offWidth=4).
prop_dpIPS32NotLarger :: Property
prop_dpIPS32NotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords =
        optimalIPSRecords Offset32 (SourceFileContents source) (TargetFileContents target)
      greedyRecords = splitMax 0xFFFF (diffHunks source target)
      dynamicProgrammingSize = ipsEncodedSize 4 dynamicProgrammingRecords
      greedySize = ipsEncodedSize 4 greedyRecords
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

prop_gdiff :: Property
prop_gdiff = forAll genPair $ \(source, target) ->
  let patch = GDIFF.createGDIFF (SourceFileContents source) (TargetFileContents target)
  in case GDIFF.parseGDIFF patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> GDIFF.applyGDIFF parsed (SourceFileContents source) === TargetFileContents target

prop_apsGba :: Property
prop_apsGba = forAll genPair $ \(source, target) ->
  let patch = APSGBA.createAPSGBA (SourceFileContents source) (TargetFileContents target)
  in case APSGBA.parseAPSGBA patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile APSGBA.applyAPSGBA parsed source
         pure $ result === target

----------------------------------------------------------------------------
-- Formats with truncation support (any size combination)
----------------------------------------------------------------------------

prop_ips32 :: Property
prop_ips32 = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS32) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Left ipsPatch) ->
        IPS.applyIPS (SourceFileContents source) ipsPatch === Right (TargetFileContents target)
      Right (Right _ebpPatch) ->
        counterexample "test fixture unexpectedly EBP" $ property False

prop_ebp :: Property
prop_ebp = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateEBP) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Right ebpPatch) ->
        IPS.applyIPS (SourceFileContents source) (ebpBasePatch ebpPatch) === Right (TargetFileContents target)
      Right (Left _ipsPatch) ->
        counterexample "test fixture unexpectedly plain IPS" $ property False

-- Direct formats: no truncation, target must be >= source
prop_ppf3 :: Property
prop_ppf3 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePPF3) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PPF.parsePatch patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> PPF.applyPatchMemory parsed (SourceFileContents source) === Right (TargetFileContents target)

prop_pmsr :: Property
prop_pmsr = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePMSR) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PMSR.parsePMSR patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile PMSR.applyPMSR parsed source
         pure $ result === target

prop_ninja1 :: Property
prop_ninja1 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateNINJA1) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile NINJA1.applyNINJA1 parsed source
         pure $ result === target

prop_ninja1Hashes :: Property
prop_ninja1Hashes = forAll genPairNoShrink $ \(source, _) ->
  not (ByteString.null source) ==>
  case createFromMemory (CreateDirect CreateNINJA1) (SourceFileContents source) (TargetFileContents source) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed ->
         NINJA1.ninja1SourceCRC parsed === Just (rustyCRC32 source) .&&.
         NINJA1.ninja1SourceMD5 parsed === Just (md5 source) .&&.
         NINJA1.ninja1SourceSHA1 parsed === Just (sha1 source)

-- DPS: differential, no truncation
prop_dps :: Property
prop_dps = forAll genPairNoShrink $ \(source, target) ->
  let patch = resultBytes (DPS.createDPS (SourceFileContents source) (TargetFileContents target) "" "" "" DPS.DPSStable)
  in case DPS.parseDPS patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> DPS.applyDPS parsed (SourceFileContents source) === TargetFileContents target

prop_rup :: Property
prop_rup = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) emptyRupInfo RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile RUP.applyRUP parsed source
         pure $ result === target

prop_rupHashes :: Property
prop_rupHashes = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) emptyRupInfo RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed ->
         RUP.rupSourceMD5 parsed === Just (unMD5Hash (md5 source)) .&&.
         RUP.rupTargetMD5 parsed === Just (unMD5Hash (md5 target))

-- PCHTXT: pure direct, no truncation
prop_pchtxt :: Property
prop_pchtxt = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePCHTXT) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PCHTXT.parsePCHTXT patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile PCHTXT.applyPCHTXT parsed source
         pure $ result === target

-- APS-N64: pure direct, no truncation
prop_apsN64 :: Property
prop_apsN64 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateAPSN64) (SourceFileContents source) (TargetFileContents target) defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case APSN64.parseAPSN64 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile APSN64.applyAPSN64 parsed source
         pure $ result === target

----------------------------------------------------------------------------
-- BPS efficiency properties
----------------------------------------------------------------------------

-- | Block move: 4 KB of data moves from offset 0x1000 to offset 0x8000.
-- The rolling-hash diff should emit SourceCopy, producing a small patch
-- rather than 4 KB of literal bytes.
prop_bpsBlockMove :: Property
prop_bpsBlockMove = once $
  let blockSize = 4096
      block = ByteString.pack [fromIntegral ((index * 7 + 3) `mod` 251) | index <- [0..blockSize-1] :: [Int]]
      padding1 = 0x1000
      padding2 = 0x8000
      sourceLength = padding2 + blockSize
      source = ByteString.replicate padding1 0 <> block <> ByteString.replicate (sourceLength - padding1 - blockSize) 0
      target = ByteString.replicate padding2 0 <> block
      patch = BPS.createBPS (SourceFileContents source) (TargetFileContents target) ByteString.empty
  in counterexample ("patch size: " ++ show (ByteString.length (unPatchFileContents patch))
                      ++ " (block: " ++ show blockSize ++ ")") $
     conjoin
       [ case BPS.parseBPS patch of
           Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
           Right parsed -> BPS.applyBPS parsed (SourceFileContents source) === Right (TargetFileContents target)
       , property (ByteString.length (unPatchFileContents patch) < 1024)
       ]

-- | Patch size should not regress: a random diff with the rolling-hash
-- algorithm must produce patches no larger than a pure-literal encoding
-- (TargetRead for every byte), which costs targetLen + small overhead.
prop_bpsNoSizeRegression :: Property
prop_bpsNoSizeRegression = forAll genPair $ \(source, target) ->
  let patch = BPS.createBPS (SourceFileContents source) (TargetFileContents target) ByteString.empty
      maxPatchSize = ByteString.length target + 100
      patchSize = ByteString.length (unPatchFileContents patch)
  in counterexample ("patch size: " ++ show patchSize
                      ++ ", max: " ++ show maxPatchSize) $
     patchSize <= maxPatchSize

----------------------------------------------------------------------------
-- PCHTXT parse unit tests
----------------------------------------------------------------------------

parsePchtxtEscapes :: IO ()
parsePchtxtEscapes = do
  raw <- ByteString.readFile "test/data/pchtxt/escapes.pchtxt"
  case PCHTXT.parsePCHTXT (PatchFileContents raw) of
    Left slapError -> assertEqual ("parse failed: " ++ renderSlapError slapError) True False
    Right parsed -> assertEqual "expected 2 entries" 2
      (length (concatMap PCHTXT.pchtxtBlockEntries (PCHTXT.pchtxtBlocks parsed)))

parsePchtxtSphinx :: IO ()
parsePchtxtSphinx = do
  raw <- ByteString.readFile "test/data/pchtxt/sphinx.pchtxt"
  case PCHTXT.parsePCHTXT (PatchFileContents raw) of
    Left slapError -> assertEqual ("parse failed: " ++ renderSlapError slapError) True False
    Right parsed -> do
      assertEqual "expected nsobid" True (PCHTXT.pchtxtNsobid parsed /= Nothing)
      case PCHTXT.pchtxtBlocks parsed of
        [block] -> assertEqual "block should be disabled" False (PCHTXT.pchtxtBlockEnabled block)
        blocks  -> assertEqual ("expected 1 block, got " ++ show (length blocks)) 1 (length blocks)
