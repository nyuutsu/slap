module Main (main) where

import qualified Slap.BPS.Apply as BPS
import qualified Slap.BPS.Create as BPS
import qualified Slap.BPS.Parse as BPS
import qualified Slap.BPS.Types as BPS
import qualified Slap.IPS.Apply as IPS
import qualified Slap.IPS.Parse as IPS
import Slap.IPS.Create (avoidSentinel, optimalIPSRecords)
import qualified Slap.UPS.Apply as UPS
import qualified Slap.UPS.Create as UPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.PMSR.Parse as PMSR
import qualified Slap.PMSR.Apply as PMSR
import qualified Slap.NINJA1.Types as NINJA1
import qualified Slap.NINJA1.Parse as NINJA1
import qualified Slap.NINJA1.Apply as NINJA1
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
import qualified Slap.VCDIFF.Parse as VCDIFF
import qualified Slap.BSDiff.Parse as BSDiff
import qualified Slap.XDelta1.Parse as XDelta1
import qualified Slap.PCHTXT.Types as PCHTXT
import qualified Slap.PCHTXT.Parse as PCHTXT
import qualified Slap.PCHTXT.Apply as PCHTXT

import Slap.Binary (md5, sha1, diffHunks)
import Slap.Measure (Offset(..), FileSize(..),
                      Hunk(..), EncodedHunk(..), UndoHunk(..))
import Slap.FFI (rustyCRC32)
import Slap.SomePatch (SomePatch(..), ApplyStrategy(..), parseSome)
import Slap.Convert (PatchContents(..), CreateFormat(..), PatchField(..),
                      FormatSpecification(..), CreateMeta(..),
                      emptyContents, formatSpecification, defaultMeta,
                      canConvert, convertDirect, conversionNotes, createFromMemory)

import Data.ByteString (ByteString)
import Data.List (isInfixOf, isPrefixOf)
import qualified Data.ByteString as ByteString
import qualified Data.Set as Set
import System.Directory (getTemporaryDirectory, removeFile)
import System.IO (hClose, openBinaryTempFile)
import Test.Tasty
import Test.Tasty.HUnit (testCase, assertBool)
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
      , testProperty "parse-truncated" prop_pchtxtTrunc
      , testCase "parse-escapes" parsePchtxtEscapes
      , testCase "parse-sphinx" parsePchtxtSphinx ]
  , testGroup "VCDIFF"
      [ testProperty "parse-truncated" prop_vcdiffTrunc ]
  , testGroup "BSDiff"
      [ testProperty "parse-truncated" prop_bsdiffTrunc ]
  , testGroup "XDelta1"
      [ testProperty "parse-truncated" prop_xdelta1Trunc ]
  , testGroup "Identity"
      [ testProperty name (prop_identity format)
      | (name, format) <- allCreateFormats
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
genByteString :: Gen ByteString
genByteString = frequency
  [ (1, pure ByteString.empty)
  , (2, ByteString.singleton <$> arbitrary)
  , (5, sized $ \sizeHint -> do
      byteCount <- choose (0, min (sizeHint * 64) 65536)
      ByteString.pack <$> vectorOf byteCount arbitrary)
  ]

-- | Arbitrary (source, target) pair with no size constraints.
genPair :: Gen (ByteString, ByteString)
genPair = (,) <$> genByteString <*> genByteString

-- | (source, target) where len(target) >= len(source).
-- Pure direct formats that lack truncation support can only grow or stay same-size.
-- Affected: PPF3, PMSR, NINJA1, DPS, APS-N64.
genPairNoShrink :: Gen (ByteString, ByteString)
genPairNoShrink = do
  shorter <- genByteString
  longer <- genByteString
  pure $ if ByteString.length shorter <= ByteString.length longer then (shorter, longer) else (longer, shorter)

-- | (source, target) of equal length.  UPS undo is only lossless when
-- source and target sizes match (the normal ROM patching case).
genSameSizePair :: Gen (ByteString, ByteString)
genSameSizePair = do
  source <- genByteString
  target <- ByteString.pack <$> vectorOf (ByteString.length source) arbitrary
  pure (source, target)

-- | Apply a direct-format patch via temp file, return result bytes.
applyViaFile :: (patch -> FilePath -> IO result) -> patch -> ByteString -> IO ByteString
applyViaFile applyFunction parsed source = do
  directory <- getTemporaryDirectory
  (temporary, handle) <- openBinaryTempFile directory "slap-prop"
  ByteString.hPut handle source
  hClose handle
  _ <- applyFunction parsed temporary
  output <- ByteString.readFile temporary
  removeFile temporary
  pure output

----------------------------------------------------------------------------
-- Delta formats: handle any size combination
----------------------------------------------------------------------------

prop_bps :: Property
prop_bps = forAll genPair $ \(source, target) ->
  let patch = BPS.createBPS source target ByteString.empty
  in case BPS.parseBPS patch >>= \parsed -> BPS.applyBPS parsed source of
       Left errorMessage     -> counterexample errorMessage $ property False
       Right result -> result === target

prop_bpsMetadata :: Property
prop_bpsMetadata = forAll genPair $ \(source, target) ->
  forAll genByteString $ \meta ->
    let patch = BPS.createBPS source target meta
    in case BPS.parseBPS patch of
         Left errorMessage     -> counterexample errorMessage $ property False
         Right parsed -> BPS.bpsMetadata parsed === meta

prop_ups :: Property
prop_ups = forAll genPair $ \(source, target) ->
  let patch = UPS.createUPS source target
  in case UPS.parseUPS patch of
       Left errorMessage     -> counterexample errorMessage $ property False
       Right parsed -> UPS.applyUPS parsed source === target

prop_ips :: Property
prop_ips = forAll genPair $ \(source, target) ->
  case createFromMemory CreateIPS source target defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
      Right parsed -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS parsed source
        pure $ result === target

-- | Source and target that differ starting at exactly offset 0x454F46.
genEofPair :: Gen (ByteString, ByteString)
genEofPair = do
  let eofOffset = 0x454F46
  count <- choose (1, 100)
  diffBytes <- ByteString.pack <$> vectorOf count (choose (1, 255))
  let source = ByteString.replicate (eofOffset + count) 0
      target = ByteString.replicate eofOffset 0 <> diffBytes
  pure (source, target)

prop_ipsEofCollision :: Property
prop_ipsEofCollision = withNumTests 20 $ forAll genEofPair $ \(source, target) ->
  case createFromMemory CreateIPS source target defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
      Right parsed -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS parsed source
        pure $ result === target

prop_avoidSentinel :: Property
prop_avoidSentinel = property $
  let source = ByteString.pack [0, 1, 2, 3, 4, 5, 6, 7]
  in conjoin
    [ -- Record at sentinel is shifted back
      avoidSentinel 5 source [EncodedHunk 5 (ByteString.pack [0xFF])]
        === [EncodedHunk 4 (ByteString.pack [4, 0xFF])]
    , -- Record NOT at sentinel is unchanged
      avoidSentinel 5 source [EncodedHunk 3 (ByteString.pack [0xAA])]
        === [EncodedHunk 3 (ByteString.pack [0xAA])]
    , -- Source too short: no-op
      avoidSentinel 5 ByteString.empty [EncodedHunk 5 (ByteString.pack [0xFF])]
        === [EncodedHunk 5 (ByteString.pack [0xFF])]
    , -- Sentinel at offset 0: can't extend backward, no-op
      avoidSentinel 0 source [EncodedHunk 0 (ByteString.pack [0xFF])]
        === [EncodedHunk 0 (ByteString.pack [0xFF])]
    ]

-- | Split hunks at maxSize boundaries (same logic as Slap.Convert.splitHunks).
splitMax :: Int -> [Hunk] -> [EncodedHunk]
splitMax maxRecordSize = concatMap splitRecord . map hunkToEncoded
  where
    hunkToEncoded (Hunk hunkOffset hunkPayload) = EncodedHunk (fromIntegral (unOffset hunkOffset)) hunkPayload
    splitRecord (EncodedHunk hunkOffset hunkPayload)
      | ByteString.length hunkPayload <= maxRecordSize = [EncodedHunk hunkOffset hunkPayload]
      | otherwise =
          let (chunk, remaining) = ByteString.splitAt maxRecordSize hunkPayload
          in EncodedHunk hunkOffset chunk : splitRecord (EncodedHunk (hunkOffset + maxRecordSize) remaining)

-- | Total encoded IPS record size (excluding magic/EOF marker).
ipsEncodedSize :: Int -> [EncodedHunk] -> Int
ipsEncodedSize offWidth = sum . map recordSize
  where
    recordSize (EncodedHunk _ payload)
      | ByteString.length payload >= 3, ByteString.all (== ByteString.index payload 0) payload = offWidth + 5
      | otherwise = offWidth + 2 + ByteString.length payload

-- | DP patch size must not exceed greedy patch size for IPS (offWidth=3).
prop_dpNotLarger :: Property
prop_dpNotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords     = optimalIPSRecords 3 source target
      greedyRecords = splitMax 0xFFFF (diffHunks source target)
      dynamicProgrammingSize     = ipsEncodedSize 3 dynamicProgrammingRecords
      greedySize = ipsEncodedSize 3 greedyRecords
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

-- | DP patch size must not exceed greedy patch size for IPS32 (offWidth=4).
prop_dpIPS32NotLarger :: Property
prop_dpIPS32NotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords     = optimalIPSRecords 4 source target
      greedyRecords = splitMax 0xFFFF (diffHunks source target)
      dynamicProgrammingSize     = ipsEncodedSize 4 dynamicProgrammingRecords
      greedySize = ipsEncodedSize 4 greedyRecords
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

prop_gdiff :: Property
prop_gdiff = forAll genPair $ \(source, target) ->
  let patch = GDIFF.createGDIFF source target
  in case GDIFF.parseGDIFF patch >>= \parsed -> GDIFF.applyGDIFF parsed source of
       Left errorMessage     -> counterexample errorMessage $ property False
       Right result -> result === target

prop_apsGba :: Property
prop_apsGba = forAll genPair $ \(source, target) ->
  let patch = APSGBA.createAPSGBA source target
  in case APSGBA.parseAPSGBA patch of
       Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile APSGBA.applyAPSGBA parsed source
         pure $ result === target

----------------------------------------------------------------------------
-- Formats with truncation support (any size combination)
----------------------------------------------------------------------------

prop_ips32 :: Property
prop_ips32 = forAll genPair $ \(source, target) ->
  case createFromMemory CreateIPS32 source target defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
      Right parsed -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS parsed source
        pure $ result === target

prop_ebp :: Property
prop_ebp = forAll genPair $ \(source, target) ->
  case createFromMemory CreateEBP source target defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case IPS.parseIPS patch of
      Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
      Right parsed -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS parsed source
        pure $ result === target

-- Direct formats: no truncation, target must be >= source
prop_ppf3 :: Property
prop_ppf3 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreatePPF3 source target defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case PPF.parsePatch patch of
       Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile PPF.applyPatch parsed source
         pure $ result === target

prop_pmsr :: Property
prop_pmsr = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreatePMSR source target defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case PMSR.parsePMSR patch of
       Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile PMSR.applyPMSR parsed source
         pure $ result === target

prop_ninja1 :: Property
prop_ninja1 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreateNINJA1 source target defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case NINJA1.parseNINJA1 patch of
       Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile NINJA1.applyNINJA1 parsed source
         pure $ result === target

prop_ninja1Hashes :: Property
prop_ninja1Hashes = forAll genPairNoShrink $ \(source, _) ->
  not (ByteString.null source) ==>
  case createFromMemory CreateNINJA1 source source defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case NINJA1.parseNINJA1 patch of
       Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
       Right parsed ->
         NINJA1.ninja1SourceCRC parsed === Just (rustyCRC32 source) .&&.
         NINJA1.ninja1SourceMD5 parsed === Just (md5 source) .&&.
         NINJA1.ninja1SourceSHA1 parsed === Just (sha1 source)

-- DPS: direct with extension, but no truncation
prop_dps :: Property
prop_dps = forAll genPairNoShrink $ \(source, target) ->
  let patch = DPS.createDPS source target "" "" "" DPS.DPSStable
  in case DPS.parseDPS patch >>= \parsed -> DPS.applyDPS parsed source of
       Left errorMessage     -> counterexample errorMessage $ property False
       Right result -> result === target

prop_rup :: Property
prop_rup = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP source target emptyRupInfo 0
  in case RUP.parseRUP patch of
       Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile RUP.applyRUP parsed source
         pure $ result === target

prop_rupHashes :: Property
prop_rupHashes = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP source target emptyRupInfo 0
  in case RUP.parseRUP patch of
       Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
       Right parsed ->
         RUP.rupSourceMD5 parsed === Just (md5 source) .&&.
         RUP.rupTargetMD5 parsed === Just (md5 target)

-- PCHTXT: pure direct, no truncation
prop_pchtxt :: Property
prop_pchtxt = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreatePCHTXT source target defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case PCHTXT.parsePCHTXT patch of
       Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile PCHTXT.applyPCHTXT parsed source
         pure $ result === target

-- APS-N64: pure direct, no truncation
prop_apsN64 :: Property
prop_apsN64 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreateAPSN64 source target defaultMeta of
    Left errorMessage -> counterexample ("create: " ++ errorMessage) $ property False
    Right patch -> case APSN64.parseAPSN64 patch of
       Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile APSN64.applyAPSN64 parsed source
         pure $ result === target

----------------------------------------------------------------------------
-- Identity: create(src, src) -> parse -> apply == src
----------------------------------------------------------------------------

allCreateFormats :: [(String, CreateFormat)]
allCreateFormats =
  [ ("BPS",     CreateBPS)
  , ("IPS",     CreateIPS)
  , ("IPS32",   CreateIPS32)
  , ("EBP",     CreateEBP)
  , ("UPS",     CreateUPS)
  , ("PPF3",    CreatePPF3)
  , ("PMSR",    CreatePMSR)
  , ("NINJA1",  CreateNINJA1)
  , ("DPS",     CreateDPS)
  , ("RUP",     CreateRUP)
  , ("APS-N64", CreateAPSN64)
  , ("APS-GBA", CreateAPSGBA)
  , ("GDIFF",   CreateGDIFF)
  , ("PCHTXT",  CreatePCHTXT)
  ]

-- | For any non-empty source, create(src, src) should be an identity patch.
prop_identity :: CreateFormat -> Property
prop_identity format = forAll genByteString $ \source -> not (ByteString.null source) ==>
  case createFromMemory format source source defaultMeta of
    Left _ -> discard
    Right patch -> case parseSome patch of
      Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
      Right parsed -> ioProperty $ do
        result <- applySomePatch parsed source
        pure $ case result of
          Left errorMessage  -> counterexample ("apply: " ++ errorMessage) $ property False
          Right out -> out === source

-- | Apply through the SomePatch closure, handling both InMemory and InPlace.
applySomePatch :: SomePatch -> ByteString -> IO (Either String ByteString)
applySomePatch somePatch source = case patchApply somePatch of
  InMemory { inMemoryApply = apply } -> apply source
  InPlace action -> Right <$> applyViaFile (\() filePath -> action filePath) () source

----------------------------------------------------------------------------
-- Undo: create -> apply -> undo == original
----------------------------------------------------------------------------

-- | UPS XOR is symmetric: applying the same patch to the target yields
-- the source.  Only holds for same-size inputs (different sizes lose
-- information in the size field).
prop_upsUndo :: Property
prop_upsUndo = forAll genSameSizePair $ \(source, target) ->
  let patch = UPS.createUPS source target
  in case UPS.parseUPS patch of
       Left errorMessage     -> counterexample errorMessage $ property False
       Right parsed -> UPS.applyUPS parsed (UPS.applyUPS parsed source) === source

-- | PPF3 with undo data: apply then undo recovers the original.
-- Same-size pairs only — PPF3 undo writes back original bytes but can't
-- truncate the file, so growth is irreversible.
prop_ppf3Undo :: Property
prop_ppf3Undo = forAll genSameSizePair $ \(source, target) -> not (ByteString.null source) ==>
  case createFromMemory CreatePPF3 source target (defaultMeta { metaUndo = True }) of
    Left _ -> discard
    Right patch -> case PPF.parsePatch patch of
      Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
      Right parsed -> ioProperty $ do
        let applied = PPF.applyPatchMemory parsed source
        result <- undoViaFile (PPF.undoPatch parsed) applied
        pure $ case result of
          Left errorMessage  -> counterexample ("undo: " ++ errorMessage) $ property False
          Right out -> out === source

-- | Write bytes to a temp file, run an undo function, read back.
undoViaFile :: (FilePath -> IO (Either String Int)) -> ByteString -> IO (Either String ByteString)
undoViaFile undoFunction target = do
  directory <- getTemporaryDirectory
  (temporary, handle) <- openBinaryTempFile directory "slap-undo"
  ByteString.hPut handle target
  hClose handle
  result <- undoFunction temporary
  case result of
    Left errorMessage -> removeFile temporary >> pure (Left errorMessage)
    Right _  -> do
      output <- ByteString.readFile temporary
      removeFile temporary
      pure (Right output)

----------------------------------------------------------------------------
-- Contract properties
----------------------------------------------------------------------------

-- | Direct formats that go through buildContents -> encodeDirect.
directFormats :: [CreateFormat]
directFormats =
  [CreateIPS, CreateIPS32, CreateEBP, CreatePPF3, CreateNINJA1, CreatePMSR, CreatePCHTXT, CreateAPSN64]

-- | PatchContents with every field populated.
fullContents :: PatchContents
fullContents = PatchContents
  { contentsRecords     = [Hunk (Offset 0) (ByteString.pack [0xFF])]
  , contentsDescription = Just (ByteString.pack [0x74, 0x65, 0x73, 0x74])
  , contentsSourceCRC32 = Just 0xDEADBEEF
  , contentsSourceMD5   = Just (ByteString.replicate 16 0xAA)
  , contentsSourceSHA1  = Just (ByteString.replicate 20 0xBB)
  , contentsDestinationSize    = Just (FileSize 1024)
  , contentsValidation  = Just (ByteString.replicate 1024 0)
  , contentsUndoData    = Just [UndoHunk (Offset 0) (ByteString.pack [0x00]) (ByteString.pack [0xFF])]
  , contentsTruncation  = Just (FileSize 512)
  , contentsEBPMeta     = Just (ByteString.pack [0x7B, 0x7D])
  , contentsRomType     = Just 0
  , contentsImageType   = Nothing
  , contentsFileIdDiz   = Nothing
  , contentsPCHTXTBlocks = Nothing
  , contentsNINJA1Compressed = Nothing
  , contentsMetadata = Nothing
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
          -- filter to only dropped-field notes; interop notes are tested separately
          droppedNotes = filter ("note: dropping" `isPrefixOf`) (conversionNotes trimmed format spec defaultMeta)
      in droppedNotes === []
  | format <- directFormats
  ]

-- | NINJA1 requires hashes -- empty contents must fail.
prop_ninja1RejectsEmpty :: Property
prop_ninja1RejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpecification CreateNINJA1 False False))

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
  in property $ case convertDirect patchContent CreateIPS defaultMeta of
       Left errorMessage -> "collides with sentinel" `isInfixOf` errorMessage
       Right _  -> False

-- | Direct conversion to IPS32 must reject a record at the EEOF sentinel offset.
prop_ips32SentinelDirect :: Property
prop_ips32SentinelDirect =
  let patchContent = emptyContents [Hunk (Offset 0x45454F46) (ByteString.pack [0xFF])]
  in property $ case convertDirect patchContent CreateIPS32 defaultMeta of
       Left errorMessage -> "collides with sentinel" `isInfixOf` errorMessage
       Right _  -> False

-- | Create path (with source bytes) must handle the sentinel offset correctly.
prop_ipsSentinelWithSource :: Property
prop_ipsSentinelWithSource =
  let eofOffset = 0x454F46
      source = ByteString.replicate (eofOffset + 1) 0
      target = ByteString.replicate eofOffset 0 <> ByteString.pack [0xFF]
  in case createFromMemory CreateIPS source target defaultMeta of
       Left errorMessage -> counterexample ("create should succeed: " ++ errorMessage) $ property False
       Right patch -> case IPS.parseIPS patch of
         Left errorMessage     -> counterexample ("parse: " ++ errorMessage) $ property False
         Right parsed -> ioProperty $ do
           result <- applyViaFile IPS.applyIPS parsed source
           pure $ result === target

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
truncated parseFunction patch =
  forAll (choose (0, ByteString.length patch - 1)) $ \truncationLength ->
    case parseFunction (ByteString.take truncationLength patch) of
      Left _  -> property True
      Right _ -> property True

prop_bpsTrunc :: Property
prop_bpsTrunc = forAll genPair $ \(source, target) ->
  truncated BPS.parseBPS (BPS.createBPS source target ByteString.empty)

-- | Block move: 4 KB of data moves from offset 0x1000 to offset 0x8000.
-- The rolling-hash diff should emit SourceCopy, producing a small patch
-- rather than 4 KB of literal bytes.
prop_bpsBlockMove :: Property
prop_bpsBlockMove = once $
  let blockSize = 4096
      -- Distinctive block content that won't match surrounding zeros
      block = ByteString.pack [fromIntegral ((index * 7 + 3) `mod` 251) | index <- [0..blockSize-1] :: [Int]]
      padding1  = 0x1000
      padding2  = 0x8000
      sourceLength = padding2 + blockSize
      source = ByteString.replicate padding1 0 <> block <> ByteString.replicate (sourceLength - padding1 - blockSize) 0
      target = ByteString.replicate padding2 0 <> block
      patch  = BPS.createBPS source target ByteString.empty
  in counterexample ("patch size: " ++ show (ByteString.length patch)
                      ++ " (block: " ++ show blockSize ++ ")") $
     conjoin
       [ case BPS.parseBPS patch >>= \parsed -> BPS.applyBPS parsed source of
           Left errorMessage     -> counterexample errorMessage $ property False
           Right result -> result === target
       , property (ByteString.length patch < 1024)
       ]

-- | Patch size should not regress: a random diff with the rolling-hash
-- algorithm must produce patches no larger than a pure-literal encoding
-- (TargetRead for every byte), which costs targetLen + small overhead.
prop_bpsNoSizeRegression :: Property
prop_bpsNoSizeRegression = forAll genPair $ \(source, target) ->
  let patch = BPS.createBPS source target ByteString.empty
      -- Worst case: entire target as TargetRead + BPS header/footer
      maxPatchSize = ByteString.length target + 100
  in counterexample ("patch size: " ++ show (ByteString.length patch)
                      ++ ", max: " ++ show maxPatchSize) $
     ByteString.length patch <= maxPatchSize

prop_ipsTrunc :: Property
prop_ipsTrunc = forAll genPair $ \(source, target) ->
  case createFromMemory CreateIPS source target defaultMeta of
    Left _ -> discard
    Right patch -> truncated IPS.parseIPS patch

prop_ips32Trunc :: Property
prop_ips32Trunc = forAll genPair $ \(source, target) ->
  case createFromMemory CreateIPS32 source target defaultMeta of
    Left _ -> discard
    Right patch -> truncated IPS.parseIPS patch

prop_ebpTrunc :: Property
prop_ebpTrunc = forAll genPair $ \(source, target) ->
  case createFromMemory CreateEBP source target defaultMeta of
    Left _ -> discard
    Right patch -> truncated IPS.parseIPS patch

prop_upsTrunc :: Property
prop_upsTrunc = forAll genPair $ \(source, target) ->
  truncated UPS.parseUPS (UPS.createUPS source target)

prop_ppf3Trunc :: Property
prop_ppf3Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreatePPF3 source target defaultMeta of
    Left _ -> discard
    Right patch -> truncated PPF.parsePatch patch

prop_pmsrTrunc :: Property
prop_pmsrTrunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreatePMSR source target defaultMeta of
    Left _ -> discard
    Right patch -> truncated PMSR.parsePMSR patch

prop_ninja1Trunc :: Property
prop_ninja1Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreateNINJA1 source target defaultMeta of
    Left _ -> discard
    Right patch -> truncated NINJA1.parseNINJA1 patch

prop_dpsTrunc :: Property
prop_dpsTrunc = forAll genPairNoShrink $ \(source, target) ->
  truncated DPS.parseDPS (DPS.createDPS source target "" "" "" DPS.DPSStable)

prop_rupTrunc :: Property
prop_rupTrunc = forAll genPair $ \(source, target) ->
  truncated RUP.parseRUP (RUP.createRUP source target emptyRupInfo 0)

prop_apsN64Trunc :: Property
prop_apsN64Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreateAPSN64 source target defaultMeta of
    Left _ -> discard
    Right patch -> truncated APSN64.parseAPSN64 patch

prop_apsGbaTrunc :: Property
prop_apsGbaTrunc = forAll genPair $ \(source, target) ->
  truncated APSGBA.parseAPSGBA (APSGBA.createAPSGBA source target)

prop_gdiffTrunc :: Property
prop_gdiffTrunc = forAll genPair $ \(source, target) ->
  truncated GDIFF.parseGDIFF (GDIFF.createGDIFF source target)

prop_pchtxtTrunc :: Property
prop_pchtxtTrunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory CreatePCHTXT source target defaultMeta of
    Left _ -> discard
    Right patch -> truncated PCHTXT.parsePCHTXT patch

-- | Parse escapes.pchtxt: exercises quoted string escapes (\n, \t, \\, \").
parsePchtxtEscapes :: IO ()
parsePchtxtEscapes = do
  raw <- ByteString.readFile "test/data/pchtxt/escapes.pchtxt"
  case PCHTXT.parsePCHTXT raw of
    Left errorMessage     -> assertBool ("parse failed: " ++ errorMessage) False
    Right parsed -> assertBool "expected 2 entries"
      (length (concatMap PCHTXT.pchtxtBlockEntries (PCHTXT.pchtxtBlocks parsed)) == 2)

-- | Parse sphinx.pchtxt: exercises @nsobid, @flag offset_shift, @disabled, @stop.
parsePchtxtSphinx :: IO ()
parsePchtxtSphinx = do
  raw <- ByteString.readFile "test/data/pchtxt/sphinx.pchtxt"
  case PCHTXT.parsePCHTXT raw of
    Left errorMessage     -> assertBool ("parse failed: " ++ errorMessage) False
    Right parsed -> do
      assertBool "expected nsobid" (PCHTXT.pchtxtNsobid parsed /= Nothing)
      case PCHTXT.pchtxtBlocks parsed of
        [block] -> assertBool "block should be disabled" (not (PCHTXT.pchtxtBlockEnabled block))
        blocks  -> assertBool ("expected 1 block, got " ++ show (length blocks)) False

----------------------------------------------------------------------------
-- Consume-only formats: truncation on real test data
----------------------------------------------------------------------------

-- | Truncate a real patch file from disk to random lengths.
-- These formats have no create function; use known-good patches instead.
truncatedFile :: (ByteString -> Either String a) -> FilePath -> Property
truncatedFile parseFunction path = ioProperty $ do
  patchBytes <- ByteString.readFile path
  pure $ forAll (choose (0, ByteString.length patchBytes - 1)) $ \truncationLength ->
    case parseFunction (ByteString.take truncationLength patchBytes) of
      Left _  -> property True
      Right _ -> property True

prop_vcdiffTrunc :: Property
prop_vcdiffTrunc = truncatedFile VCDIFF.parseVCDIFF "test/data/dm4y/patch.vcdiff"

prop_bsdiffTrunc :: Property
prop_bsdiffTrunc = truncatedFile BSDiff.parseBSDiff "test/data/dm4y/patch.bsdiff"

prop_xdelta1Trunc :: Property
prop_xdelta1Trunc = truncatedFile XDelta1.parseXDelta1 "test/data/dm4y/patch.xdelta1"
