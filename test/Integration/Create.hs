{-# LANGUAGE OverloadedStrings #-}

module Integration.Create (createTests) where

import Integration.Bootstrap (BootstrapTargets, lookupBootstrapTarget)
import Integration.HeavyTests (FixtureName(..), differentialCreateIsExpensive)
import Integration.Helpers (assertFailureT)
import Integration.Helpers
  ( Tier
  , isHeavyPath
  , restrictToTier
  , repoDir
  , parseSpecFile
  , lookupCreateFormatToken
  , sha1Hex
  , applyPatch
  , mmapRomFile
  )
import Integration.Skip
  ( GroupPlan
  , MaybeTest(..)
  , namedGroup
  , requireFixture
  )
import Slap.Convert
  (CreateFormat(..), DifferentialCreate(..), noMetadataRequested, noConstraintsRequested,
   noDialectsRequested)
import Slap.XDelta1.Types (ResolvedXDelta1FileNames, resolveXDelta1FileNames)
import Slap.Create (createPatch)
import Slap.Status (CreateResult(..), renderSlapError)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.SomePatch (parseSome)
import Slap.Text (EncodingName(EncodingUtf8))

import Data.ByteString (ByteString)
import System.FilePath ((</>))
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, assertEqual)
import qualified Data.Text as Text

-- | Create-and-round-trip in-memory: build a patch in each format
-- listed by @test/specs/create.txt@, parse it back, apply, and assert
-- the SHA1 matches the recorded target. Each row's two file
-- prerequisites become typed 'MissingFixture' skips when absent.
createTests :: Tier -> IO BootstrapTargets -> IO GroupPlan
createTests tier getTargets = do
  repo    <- repoDir
  allRows <- parseSpecFile (repo </> "test" </> "specs" </> "create.txt")
  let inTierRows = restrictToTier tier rowIsHeavy allRows
  rowMaybes <- concat <$> mapM (planCreateRow getTargets repo) inTierRows
  pure (namedGroup "create" rowMaybes)
  where
    rowIsHeavy row = case row of
      (_format : _scenario : basePath : _) -> isHeavyPath basePath
      _                                    -> False

planCreateRow :: IO BootstrapTargets -> FilePath -> [String] -> IO [MaybeTest]
planCreateRow getTargets repo fields = case fields of
  (formatString : scenario : basePath : bootstrapPath : targetSha : _)
    | Just format <- lookupCreateFormatToken formatString ->
        let absoluteBase = repo </> basePath
            absoluteBoot = repo </> bootstrapPath
            label        = formatString ++ "/" ++ scenario
            runnable     = mkRoundTripTest getTargets label format
                             absoluteBase absoluteBoot targetSha
            constructor
              | format `elem` [CreateDifferential CreateBPS, CreateDifferential CreateBSDiff]
              , differentialCreateIsExpensive (FixtureName scenario) = WillRunHeavy
              | otherwise                                            = WillRun
        in requireFixture absoluteBase $ \_ ->
           requireFixture absoluteBoot $ \_ ->
             pure [constructor runnable]
    | otherwise -> pure []  -- spec row references unknown format
  _ -> pure []

mkRoundTripTest
  :: IO BootstrapTargets
  -> String      -- ^ test label
  -> CreateFormat
  -> FilePath    -- ^ base ROM path
  -> FilePath    -- ^ bootstrap-patch path (key into the bootstrap map)
  -> String      -- ^ expected target SHA1
  -> TestTree
mkRoundTripTest getTargets label format basePath bootPath expectedTargetSha =
  testCase label $ do
    bootstrapTargets <- getTargets
    baseBytes <- mmapRomFile basePath
    let targetBytes = lookupBootstrapTarget bootstrapTargets basePath bootPath
    roundTrip format basePath bootPath baseBytes targetBytes expectedTargetSha

-- | Create a patch in @format@, parse it back, apply to @baseBytes@,
-- and assert the resulting SHA1. The two 'FilePath' arguments feed
-- 'resolveXDelta1FileNames' for the xdelta1 target only (other
-- formats receive 'Nothing' for the resolved-names slot); without
-- them, the create dispatcher would refuse with
-- 'XDelta1ConvertRequiresNames'.
roundTrip :: CreateFormat -> FilePath -> FilePath -> ByteString -> ByteString -> String -> IO ()
roundTrip format basePath bootPath baseBytes targetBytes expectedSha = do
  let resolvedXDelta1Names = resolveXDelta1NamesForRoundTrip format basePath bootPath
  case createPatch format resolvedXDelta1Names
         (InputFileContents baseBytes)
         (OutputFileContents targetBytes)
         noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError ->
      assertFailureT ("create failed: " <> renderSlapError slapError)
    Right (CreateResult patchBytes _) -> case parseSome noDialectsRequested EncodingUtf8 patchBytes of
      Left slapError ->
        assertFailureT ("re-parse failed: " <> renderSlapError slapError)
      Right parsed -> do
        result <- applyPatch parsed (InputFileContents baseBytes)
        case result of
          Left slapError ->
            assertFailureT ("re-apply failed: " <> renderSlapError slapError)
          Right (OutputFileContents output) ->
            assertEqual "SHA1 mismatch" expectedSha (sha1Hex output)

-- | Resolve the xdelta1 header-name pair for 'roundTrip' when the
-- target format is xdelta1; 'Nothing' for every other target. The
-- resolver's basename defaulting fires unconditionally here (the
-- round-trip harness never passes explicit names), so the cap check
-- is the only failure mode — and at the path-derived sizes the
-- harness uses, that's never going to trip. The 'error' fallback is
-- the test-side analogue of slap's "if this fires the porcelain is
-- broken" assertion.
resolveXDelta1NamesForRoundTrip
  :: CreateFormat -> FilePath -> FilePath -> Maybe ResolvedXDelta1FileNames
resolveXDelta1NamesForRoundTrip (CreateDifferential CreateXDelta1) basePath bootPath =
  case resolveXDelta1FileNames Nothing Nothing basePath bootPath of
    Right resolved  -> Just resolved
    Left slapError  -> error ("resolveXDelta1NamesForRoundTrip: "
                              ++ Text.unpack (renderSlapError slapError))
resolveXDelta1NamesForRoundTrip _ _ _ = Nothing
