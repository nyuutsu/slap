module Main (main) where

import qualified Patch.BPS as BPS
import qualified Patch.IPS as IPS
import Patch.IPS (avoidSentinel, optimalIPSRecords)
import qualified Patch.UPS as UPS
import qualified Patch.PMSR as PMSR
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.DPS as DPS
import qualified Patch.RUP as RUP
import qualified Patch.APS as APS
import qualified Patch.GDIFF as GDIFF
import qualified Patch.PPF.Parse as PPF
import qualified Patch.PPF.Apply as PPF
import qualified Patch.VCDIFF as VCDIFF
import qualified Patch.BSDiff as BSDiff
import qualified Patch.XDelta1 as XDelta1
import qualified Patch.PCHTXT as PCHTXT

import Patch.Binary (md5, sha1, diffHunks)
import Patch.FFI (rustyCRC32)
import Patch.SomePatch (SomePatch(..), ApplyStrategy(..), parseSome)
import Patch.Convert (PatchContents(..), CreateFormat(..), PatchField(..),
                      FormatSpec(..), CreateMeta(..),
                      emptyContents, formatSpec, defaultMeta,
                      canConvert, convertDirect, conversionNotes, createFromMemory)

import Data.ByteString (ByteString)
import Data.List (isInfixOf, isPrefixOf)
import qualified Data.ByteString as BS
import qualified Data.Set as Set
import System.Directory (getTemporaryDirectory, removeFile)
import System.IO (hClose, openBinaryTempFile)
import Test.Tasty
import Test.Tasty.QuickCheck

main :: IO ()
main = defaultMain $ testGroup "Properties"
  [ testGroup "BPS"
      [ testProperty "round-trip" prop_bps
      , testProperty "parse-truncated" prop_bpsTrunc
      , testProperty "block-move" prop_bpsBlockMove
      , testProperty "no-size-regression" prop_bpsNoSizeRegression
      , testProperty "metadata-round-trip" prop_bpsMetadata ]
  , testGroup "IPS"
      [ testProperty "round-trip" prop_ips
      , testProperty "eof-collision" prop_ipsEofCollision
      , testProperty "avoidSentinel" prop_avoidSentinel
      , testProperty "dp-not-larger" prop_dpNotLarger
      , testProperty "parse-truncated" prop_ipsTrunc ]
  , testGroup "IPS32"
      [ testProperty "round-trip" prop_ips32
      , testProperty "dp-not-larger" prop_dpIPS32NotLarger
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
      , testProperty "hashes" prop_ninja1Hashes
      , testProperty "parse-truncated" prop_ninja1Trunc ]
  , testGroup "DPS"
      [ testProperty "round-trip" prop_dps
      , testProperty "parse-truncated" prop_dpsTrunc ]
  , testGroup "RUP"
      [ testProperty "round-trip" prop_rup
      , testProperty "hashes" prop_rupHashes
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
  , testGroup "PCHTXT"
      [ testProperty "round-trip" prop_pchtxt
      , testProperty "parse-truncated" prop_pchtxtTrunc ]
  , testGroup "VCDIFF"
      [ testProperty "parse-truncated" prop_vcdiffTrunc ]
  , testGroup "BSDiff"
      [ testProperty "parse-truncated" prop_bsdiffTrunc ]
  , testGroup "XDelta1"
      [ testProperty "parse-truncated" prop_xdelta1Trunc ]
  , testGroup "Identity"
      [ testProperty name (prop_identity fmt)
      | (name, fmt) <- allCreateFormats
      ]
  , testGroup "Undo"
      [ testProperty "UPS" prop_upsUndo
      , testProperty "PPF3" prop_ppf3Undo
      ]
  , testGroup "Contracts"
      [ testProperty "canConvert-full" prop_canConvertFull
      , testProperty "no-surplus-no-notes" prop_noSurplusNoNotes
      , testProperty "ninja1-rejects-empty" prop_ninja1RejectsEmpty
      , testProperty "apsn64-rejects-empty" prop_apsn64RejectsEmpty
      , testProperty "ppf3-undo-rejects-empty" prop_ppf3UndoRejectsEmpty
      , testProperty "ppf3-validate-rejects-empty" prop_ppf3ValidateRejectsEmpty
      , testProperty "ips-sentinel-collision-direct" prop_ipsSentinelDirect
      , testProperty "ips32-sentinel-collision-direct" prop_ips32SentinelDirect
      , testProperty "ips-sentinel-with-source" prop_ipsSentinelWithSource
      ]
  ]

emptyRupInfo :: RUP.RUPInfo
emptyRupInfo = RUP.RUPInfo Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing

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
-- Pure direct formats that lack truncation support can only grow or stay same-size.
-- Affected: PPF3, PMSR, NINJA1, DPS, APS-N64.
genPairNoShrink :: Gen (ByteString, ByteString)
genPairNoShrink = do
  a <- genBS
  b <- genBS
  pure $ if BS.length a <= BS.length b then (a, b) else (b, a)

-- | (source, target) of equal length.  UPS undo is only lossless when
-- source and target sizes match (the normal ROM patching case).
genSameSizePair :: Gen (ByteString, ByteString)
genSameSizePair = do
  src <- genBS
  tgt <- BS.pack <$> vectorOf (BS.length src) arbitrary
  pure (src, tgt)

-- | Apply a direct-format patch via temp file, return result bytes.
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
  let patch = BPS.createBPS src tgt BS.empty
  in case BPS.parseBPS patch >>= \p -> BPS.applyBPS p src of
       Left err     -> counterexample err $ property False
       Right result -> result === tgt

prop_bpsMetadata :: Property
prop_bpsMetadata = forAll genPair $ \(src, tgt) ->
  forAll genBS $ \meta ->
    let patch = BPS.createBPS src tgt meta
    in case BPS.parseBPS patch of
         Left err -> counterexample err $ property False
         Right p  -> BPS.bpsMetadata p === meta

prop_ups :: Property
prop_ups = forAll genPair $ \(src, tgt) ->
  let patch = UPS.createUPS src tgt
  in case UPS.parseUPS patch of
       Left err -> counterexample err $ property False
       Right p  -> UPS.applyUPS p src === tgt

prop_ips :: Property
prop_ips = forAll genPair $ \(src, tgt) ->
  case createFromMemory CfmtIPS src tgt defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left err -> counterexample ("parse: " ++ err) $ property False
      Right p  -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS p src
        pure $ result === tgt

-- | Source and target that differ starting at exactly offset 0x454F46.
genEofPair :: Gen (ByteString, ByteString)
genEofPair = do
  let off = 0x454F46
  n <- choose (1, 100)
  diffBytes <- BS.pack <$> vectorOf n (choose (1, 255))
  let src = BS.replicate (off + n) 0
      tgt = BS.replicate off 0 <> diffBytes
  pure (src, tgt)

prop_ipsEofCollision :: Property
prop_ipsEofCollision = withMaxSuccess 20 $ forAll genEofPair $ \(src, tgt) ->
  case createFromMemory CfmtIPS src tgt defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left err -> counterexample ("parse: " ++ err) $ property False
      Right p  -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS p src
        pure $ result === tgt

prop_avoidSentinel :: Property
prop_avoidSentinel = property $
  let src = BS.pack [0, 1, 2, 3, 4, 5, 6, 7]
  in conjoin
    [ -- Record at sentinel is shifted back
      avoidSentinel 5 src [(5, BS.pack [0xFF])]
        === [(4, BS.pack [4, 0xFF])]
    , -- Record NOT at sentinel is unchanged
      avoidSentinel 5 src [(3, BS.pack [0xAA])]
        === [(3, BS.pack [0xAA])]
    , -- Source too short: no-op
      avoidSentinel 5 BS.empty [(5, BS.pack [0xFF])]
        === [(5, BS.pack [0xFF])]
    , -- Sentinel at offset 0: can't extend backward, no-op
      avoidSentinel 0 src [(0, BS.pack [0xFF])]
        === [(0, BS.pack [0xFF])]
    ]

-- | Split records at maxSize boundaries (same logic as Patch.Convert.splitRecords).
splitMax :: Int -> [(Int, ByteString)] -> [(Int, ByteString)]
splitMax maxSz = concatMap split1
  where
    split1 (off, dat)
      | BS.length dat <= maxSz = [(off, dat)]
      | otherwise =
          let (h, t) = BS.splitAt maxSz dat
          in (off, h) : split1 (off + maxSz, t)

-- | Total encoded IPS record size (excluding magic/EOF marker).
ipsEncodedSize :: Int -> [(Int, ByteString)] -> Int
ipsEncodedSize offWidth = sum . map recSz
  where
    recSz (_, d)
      | BS.length d >= 3, BS.all (== BS.index d 0) d = offWidth + 5
      | otherwise = offWidth + 2 + BS.length d

-- | DP patch size must not exceed greedy patch size for IPS (offWidth=3).
prop_dpNotLarger :: Property
prop_dpNotLarger = forAll genPair $ \(src, tgt) ->
  let dpRecs     = optimalIPSRecords 3 src tgt
      greedyRecs = splitMax 0xFFFF (diffHunks src tgt)
      dpSz       = ipsEncodedSize 3 dpRecs
      greedySz   = ipsEncodedSize 3 greedyRecs
  in counterexample ("DP: " ++ show dpSz ++ ", greedy: " ++ show greedySz) $
     dpSz <= greedySz

-- | DP patch size must not exceed greedy patch size for IPS32 (offWidth=4).
prop_dpIPS32NotLarger :: Property
prop_dpIPS32NotLarger = forAll genPair $ \(src, tgt) ->
  let dpRecs     = optimalIPSRecords 4 src tgt
      greedyRecs = splitMax 0xFFFF (diffHunks src tgt)
      dpSz       = ipsEncodedSize 4 dpRecs
      greedySz   = ipsEncodedSize 4 greedyRecs
  in counterexample ("DP: " ++ show dpSz ++ ", greedy: " ++ show greedySz) $
     dpSz <= greedySz

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
  case createFromMemory CfmtIPS32 src tgt defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left err -> counterexample ("parse: " ++ err) $ property False
      Right p  -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS p src
        pure $ result === tgt

prop_ebp :: Property
prop_ebp = forAll genPair $ \(src, tgt) ->
  case createFromMemory CfmtEBP src tgt defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left err -> counterexample ("parse: " ++ err) $ property False
      Right p  -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS p src
        pure $ result === tgt

-- Direct formats: no truncation, target must be >= source
prop_ppf3 :: Property
prop_ppf3 = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtPPF3 src tgt defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case PPF.parsePatch patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile PPF.applyPatch p src
         pure $ result === tgt

prop_pmsr :: Property
prop_pmsr = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtPMSR src tgt defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case PMSR.parsePMSR patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile PMSR.applyPMSR p src
         pure $ result === tgt

prop_ninja1 :: Property
prop_ninja1 = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtNINJA1 src tgt defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case NINJA1.parseNINJA1 patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile NINJA1.applyNINJA1 p src
         pure $ result === tgt

prop_ninja1Hashes :: Property
prop_ninja1Hashes = forAll genPairNoShrink $ \(src, _) ->
  not (BS.null src) ==>
  case createFromMemory CfmtNINJA1 src src defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case NINJA1.parseNINJA1 patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  ->
         NINJA1.n1SourceCRC p === Just (rustyCRC32 src) .&&.
         NINJA1.n1SourceMD5 p === Just (md5 src) .&&.
         NINJA1.n1SourceSHA1 p === Just (sha1 src)

-- DPS: direct with extension, but no truncation
prop_dps :: Property
prop_dps = forAll genPairNoShrink $ \(src, tgt) ->
  let patch = DPS.createDPS src tgt "" "" "" DPS.DPSStable
  in case DPS.parseDPS patch >>= \p -> DPS.applyDPS p src of
       Left err     -> counterexample err $ property False
       Right result -> result === tgt

prop_rup :: Property
prop_rup = forAll genPair $ \(src, tgt) ->
  let patch = RUP.createRUP src tgt emptyRupInfo 0
  in case RUP.parseRUP patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile RUP.applyRUP p src
         pure $ result === tgt

prop_rupHashes :: Property
prop_rupHashes = forAll genPair $ \(src, tgt) ->
  let patch = RUP.createRUP src tgt emptyRupInfo 0
  in case RUP.parseRUP patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  ->
         RUP.rupSourceMD5 p === Just (md5 src) .&&.
         RUP.rupTargetMD5 p === Just (md5 tgt)

-- PCHTXT: pure direct, no truncation
prop_pchtxt :: Property
prop_pchtxt = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtPCHTXT src tgt defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case PCHTXT.parsePCHTXT patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile PCHTXT.applyPCHTXT p src
         pure $ result === tgt

-- APS-N64: pure direct, no truncation
prop_apsN64 :: Property
prop_apsN64 = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtAPSN64 src tgt defaultMeta of
    Left err -> counterexample ("create: " ++ err) $ property False
    Right patch -> case APS.parseAPS patch of
       Left err -> counterexample ("parse: " ++ err) $ property False
       Right p  -> ioProperty $ do
         result <- applyViaFile APS.applyAPS p src
         pure $ result === tgt

----------------------------------------------------------------------------
-- Identity: create(src, src) → parse → apply == src
----------------------------------------------------------------------------

allCreateFormats :: [(String, CreateFormat)]
allCreateFormats =
  [ ("BPS",     CfmtBPS)
  , ("IPS",     CfmtIPS)
  , ("IPS32",   CfmtIPS32)
  , ("EBP",     CfmtEBP)
  , ("UPS",     CfmtUPS)
  , ("PPF3",    CfmtPPF3)
  , ("PMSR",    CfmtPMSR)
  , ("NINJA1",  CfmtNINJA1)
  , ("DPS",     CfmtDPS)
  , ("RUP",     CfmtRUP)
  , ("APS-N64", CfmtAPSN64)
  , ("APS-GBA", CfmtAPSGBA)
  , ("GDIFF",   CfmtGDIFF)
  , ("PCHTXT",  CfmtPCHTXT)
  ]

-- | For any non-empty source, create(src, src) should be an identity patch.
prop_identity :: CreateFormat -> Property
prop_identity fmt = forAll genBS $ \src -> not (BS.null src) ==>
  case createFromMemory fmt src src defaultMeta of
    Left _ -> discard
    Right patch -> case parseSome patch of
      Left err -> counterexample ("parse: " ++ err) $ property False
      Right sp -> ioProperty $ do
        result <- applySomePatch sp src
        pure $ case result of
          Left err  -> counterexample ("apply: " ++ err) $ property False
          Right out -> out === src

-- | Apply through the SomePatch closure, handling both InMemory and InPlace.
applySomePatch :: SomePatch -> ByteString -> IO (Either String ByteString)
applySomePatch sp source = case spApply sp of
  InMemory { imApply = apply } -> apply source
  InPlace f -> Right <$> applyViaFile (\() fp -> f fp) () source

----------------------------------------------------------------------------
-- Undo: create → apply → undo == original
----------------------------------------------------------------------------

-- | UPS XOR is symmetric: applying the same patch to the target yields
-- the source.  Only holds for same-size inputs (different sizes lose
-- information in the size field).
prop_upsUndo :: Property
prop_upsUndo = forAll genSameSizePair $ \(src, tgt) ->
  let patch = UPS.createUPS src tgt
  in case UPS.parseUPS patch of
       Left err -> counterexample err $ property False
       Right p  -> UPS.applyUPS p (UPS.applyUPS p src) === src

-- | PPF3 with undo data: apply then undo recovers the original.
-- Same-size pairs only — PPF3 undo writes back original bytes but can't
-- truncate the file, so growth is irreversible.
prop_ppf3Undo :: Property
prop_ppf3Undo = forAll genSameSizePair $ \(src, tgt) -> not (BS.null src) ==>
  case createFromMemory CfmtPPF3 src tgt (defaultMeta { cmUndo = True }) of
    Left _ -> discard
    Right patch -> case PPF.parsePatch patch of
      Left err -> counterexample ("parse: " ++ err) $ property False
      Right p -> ioProperty $ do
        let applied = PPF.applyPatchMemory p src
        result <- undoViaFile (PPF.undoPatch p) applied
        pure $ case result of
          Left err  -> counterexample ("undo: " ++ err) $ property False
          Right out -> out === src

-- | Write bytes to a temp file, run an undo function, read back.
undoViaFile :: (FilePath -> IO (Either String Int)) -> ByteString -> IO (Either String ByteString)
undoViaFile undoFn target = do
  dir <- getTemporaryDirectory
  (tmp, h) <- openBinaryTempFile dir "slap-undo"
  BS.hPut h target
  hClose h
  result <- undoFn tmp
  case result of
    Left err -> removeFile tmp >> pure (Left err)
    Right _  -> do
      bs <- BS.readFile tmp
      removeFile tmp
      pure (Right bs)

----------------------------------------------------------------------------
-- Contract properties
----------------------------------------------------------------------------

-- | Direct formats that go through buildContents → encodeDirect.
directFormats :: [CreateFormat]
directFormats =
  [CfmtIPS, CfmtIPS32, CfmtEBP, CfmtPPF3, CfmtNINJA1, CfmtPMSR, CfmtPCHTXT, CfmtAPSN64]

-- | PatchContents with every field populated.
fullContents :: PatchContents
fullContents = PatchContents
  { pcRecords     = [(0, BS.pack [0xFF])]
  , pcDescription = Just (BS.pack [0x74, 0x65, 0x73, 0x74])
  , pcSourceCRC32 = Just 0xDEADBEEF
  , pcSourceMD5   = Just (BS.replicate 16 0xAA)
  , pcSourceSHA1  = Just (BS.replicate 20 0xBB)
  , pcDestSize    = Just 1024
  , pcValidation  = Just (BS.replicate 1024 0)
  , pcUndoData    = Just [(0, BS.pack [0x00], BS.pack [0xFF])]
  , pcTruncation  = Just 512
  , pcEBPMeta     = Just (BS.pack [0x7B, 0x7D])
  , pcRomType     = Just 0
  , pcImageType   = Nothing
  , pcFileIdDiz   = Nothing
  , pcPCHTXTBlocks = Nothing
  , pcNINJA1Compressed = Nothing
  , pcMetadata = Nothing
  }

-- | canConvert succeeds for every direct format when all fields are present.
prop_canConvertFull :: Property
prop_canConvertFull = conjoin
  [ counterexample (show fmt) $
      canConvert fullContents (formatSpec fmt True True) === Right ()
  | fmt <- directFormats
  ]

-- | No dropped-field notes when provides exactly matches required ∪ accepted.
prop_noSurplusNoNotes :: Property
prop_noSurplusNoNotes = conjoin
  [ counterexample (show fmt) $
      let spec = formatSpec fmt True True
          kept = fsRequired spec `Set.union` fsAccepted spec
          trimmed = fullContents
            { pcDescription = if FDescription `Set.member` kept then pcDescription fullContents else Nothing
            , pcSourceCRC32 = if FSourceCRC32 `Set.member` kept then pcSourceCRC32 fullContents else Nothing
            , pcSourceMD5   = if FSourceMD5   `Set.member` kept then pcSourceMD5   fullContents else Nothing
            , pcSourceSHA1  = if FSourceSHA1  `Set.member` kept then pcSourceSHA1  fullContents else Nothing
            , pcDestSize    = if FDestSize    `Set.member` kept then pcDestSize    fullContents else Nothing
            , pcValidation  = if FValidation  `Set.member` kept then pcValidation  fullContents else Nothing
            , pcUndoData    = if FUndoData    `Set.member` kept then pcUndoData    fullContents else Nothing
            , pcTruncation  = if FTruncation  `Set.member` kept then pcTruncation  fullContents else Nothing
            , pcEBPMeta     = if FEBPMeta     `Set.member` kept then pcEBPMeta     fullContents else Nothing
            , pcRomType     = if FRomType     `Set.member` kept then pcRomType     fullContents else Nothing
            , pcImageType   = if FImageType   `Set.member` kept then pcImageType   fullContents else Nothing
            }
          -- filter to only dropped-field notes; interop notes are tested separately
          droppedNotes = filter ("note: dropping" `isPrefixOf`) (conversionNotes trimmed fmt spec defaultMeta)
      in droppedNotes === []
  | fmt <- directFormats
  ]

-- | NINJA1 requires hashes — empty contents must fail.
prop_ninja1RejectsEmpty :: Property
prop_ninja1RejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpec CfmtNINJA1 False False))

-- | APS-N64 requires dest size — empty contents must fail.
prop_apsn64RejectsEmpty :: Property
prop_apsn64RejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpec CfmtAPSN64 False False))

-- | PPF3 with undo requires undo data — empty contents must fail.
prop_ppf3UndoRejectsEmpty :: Property
prop_ppf3UndoRejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpec CfmtPPF3 True False))

-- | PPF3 with validation requires validation block — empty contents must fail.
prop_ppf3ValidateRejectsEmpty :: Property
prop_ppf3ValidateRejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpec CfmtPPF3 False True))

-- | Direct conversion to IPS must reject a record at the EOF sentinel offset.
prop_ipsSentinelDirect :: Property
prop_ipsSentinelDirect =
  let pc = emptyContents [(0x454F46, BS.pack [0xFF])]
  in property $ case convertDirect pc CfmtIPS defaultMeta of
       Left err -> "EOF marker" `isInfixOf` err
       Right _  -> False

-- | Direct conversion to IPS32 must reject a record at the EEOF sentinel offset.
prop_ips32SentinelDirect :: Property
prop_ips32SentinelDirect =
  let pc = emptyContents [(0x45454F46, BS.pack [0xFF])]
  in property $ case convertDirect pc CfmtIPS32 defaultMeta of
       Left err -> "EOF marker" `isInfixOf` err
       Right _  -> False

-- | Create path (with source bytes) must handle the sentinel offset correctly.
prop_ipsSentinelWithSource :: Property
prop_ipsSentinelWithSource =
  let off = 0x454F46
      src = BS.replicate (off + 1) 0
      tgt = BS.replicate off 0 <> BS.pack [0xFF]
  in case createFromMemory CfmtIPS src tgt defaultMeta of
       Left err -> counterexample ("create should succeed: " ++ err) $ property False
       Right patch -> case IPS.parseIPS patch of
         Left err -> counterexample ("parse: " ++ err) $ property False
         Right p  -> ioProperty $ do
           result <- applyViaFile IPS.applyIPS p src
           pure $ result === tgt

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _        = False

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
  truncated BPS.parseBPS (BPS.createBPS src tgt BS.empty)

-- | Block move: 4 KB of data moves from offset 0x1000 to offset 0x8000.
-- The rolling-hash diff should emit SourceCopy, producing a small patch
-- rather than 4 KB of literal bytes.
prop_bpsBlockMove :: Property
prop_bpsBlockMove = once $
  let blockSize = 4096
      -- Distinctive block content that won't match surrounding zeros
      block = BS.pack [fromIntegral ((i * 7 + 3) `mod` 251) | i <- [0..blockSize-1] :: [Int]]
      pad1  = 0x1000
      pad2  = 0x8000
      srcLen = pad2 + blockSize
      src   = BS.replicate pad1 0 <> block <> BS.replicate (srcLen - pad1 - blockSize) 0
      tgt   = BS.replicate pad2 0 <> block
      patch = BPS.createBPS src tgt BS.empty
  in counterexample ("patch size: " ++ show (BS.length patch)
                      ++ " (block: " ++ show blockSize ++ ")") $
     conjoin
       [ case BPS.parseBPS patch >>= \p -> BPS.applyBPS p src of
           Left err     -> counterexample err $ property False
           Right result -> result === tgt
       , property (BS.length patch < 1024)
       ]

-- | Patch size should not regress: a random diff with the rolling-hash
-- algorithm must produce patches no larger than a pure-literal encoding
-- (TargetRead for every byte), which costs targetLen + small overhead.
prop_bpsNoSizeRegression :: Property
prop_bpsNoSizeRegression = forAll genPair $ \(src, tgt) ->
  let patch = BPS.createBPS src tgt BS.empty
      -- Worst case: entire target as TargetRead + BPS header/footer
      maxSize = BS.length tgt + 100
  in counterexample ("patch size: " ++ show (BS.length patch)
                      ++ ", max: " ++ show maxSize) $
     BS.length patch <= maxSize

prop_ipsTrunc :: Property
prop_ipsTrunc = forAll genPair $ \(src, tgt) ->
  case createFromMemory CfmtIPS src tgt defaultMeta of
    Left _ -> discard
    Right patch -> truncated IPS.parseIPS patch

prop_ips32Trunc :: Property
prop_ips32Trunc = forAll genPair $ \(src, tgt) ->
  case createFromMemory CfmtIPS32 src tgt defaultMeta of
    Left _ -> discard
    Right patch -> truncated IPS.parseIPS patch

prop_ebpTrunc :: Property
prop_ebpTrunc = forAll genPair $ \(src, tgt) ->
  case createFromMemory CfmtEBP src tgt defaultMeta of
    Left _ -> discard
    Right patch -> truncated IPS.parseIPS patch

prop_upsTrunc :: Property
prop_upsTrunc = forAll genPair $ \(src, tgt) ->
  truncated UPS.parseUPS (UPS.createUPS src tgt)

prop_ppf3Trunc :: Property
prop_ppf3Trunc = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtPPF3 src tgt defaultMeta of
    Left _ -> discard
    Right patch -> truncated PPF.parsePatch patch

prop_pmsrTrunc :: Property
prop_pmsrTrunc = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtPMSR src tgt defaultMeta of
    Left _ -> discard
    Right patch -> truncated PMSR.parsePMSR patch

prop_ninja1Trunc :: Property
prop_ninja1Trunc = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtNINJA1 src tgt defaultMeta of
    Left _ -> discard
    Right patch -> truncated NINJA1.parseNINJA1 patch

prop_dpsTrunc :: Property
prop_dpsTrunc = forAll genPairNoShrink $ \(src, tgt) ->
  truncated DPS.parseDPS (DPS.createDPS src tgt "" "" "" DPS.DPSStable)

prop_rupTrunc :: Property
prop_rupTrunc = forAll genPair $ \(src, tgt) ->
  truncated RUP.parseRUP (RUP.createRUP src tgt emptyRupInfo 0)

prop_apsN64Trunc :: Property
prop_apsN64Trunc = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtAPSN64 src tgt defaultMeta of
    Left _ -> discard
    Right patch -> truncated APS.parseAPS patch

prop_apsGbaTrunc :: Property
prop_apsGbaTrunc = forAll genPair $ \(src, tgt) ->
  truncated APS.parseAPS (APS.createAPSGBA src tgt)

prop_gdiffTrunc :: Property
prop_gdiffTrunc = forAll genPair $ \(src, tgt) ->
  truncated GDIFF.parseGDIFF (GDIFF.createGDIFF src tgt)

prop_pchtxtTrunc :: Property
prop_pchtxtTrunc = forAll genPairNoShrink $ \(src, tgt) ->
  case createFromMemory CfmtPCHTXT src tgt defaultMeta of
    Left _ -> discard
    Right patch -> truncated PCHTXT.parsePCHTXT patch

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
