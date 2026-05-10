module Integration.Create (createTests) where

import Integration.Bootstrap (BootstrapTargets, lookupBootstrapTarget)
import Integration.HeavyTests (FixtureName(..), bpsCreateIsExpensive)
import Integration.Helpers
  ( Tier
  , isHeavyPath
  , restrictToTier
  , repoDir
  , parseSpecFile
  , parseCreateFormat
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
  (CreateFormat(..), DifferentialCreate(..), noMetadataRequested, noConstraintsRequested, noDialectsRequested)
import Slap.Create (createPatch)
import Slap.Error (CreateResult(..), renderSlapError)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.SomePatch (parseSome)

import Data.ByteString (ByteString)
import System.FilePath ((</>))
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

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
    | Just format <- parseCreateFormat formatString ->
        let absoluteBase = repo </> basePath
            absoluteBoot = repo </> bootstrapPath
            label        = formatString ++ "/" ++ scenario
            runnable     = mkRoundTripTest getTargets label format
                             absoluteBase absoluteBoot targetSha
            constructor
              | format == CreateDifferential CreateBPS
              , bpsCreateIsExpensive (FixtureName scenario) = WillRunHeavy
              | otherwise                                   = WillRun
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
    roundTrip format baseBytes targetBytes expectedTargetSha

-- | Create a patch in @format@, parse it back, apply to @baseBytes@,
-- and assert the resulting SHA1.
roundTrip :: CreateFormat -> ByteString -> ByteString -> String -> IO ()
roundTrip format baseBytes targetBytes expectedSha =
  case createPatch format
         (InputFileContents baseBytes)
         (OutputFileContents targetBytes)
         noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError ->
      assertFailure ("create failed: " ++ renderSlapError slapError)
    Right (CreateResult patchBytes _) -> case parseSome noDialectsRequested patchBytes of
      Left slapError ->
        assertFailure ("re-parse failed: " ++ renderSlapError slapError)
      Right parsed -> do
        result <- applyPatch parsed (InputFileContents baseBytes)
        case result of
          Left slapError ->
            assertFailure ("re-apply failed: " ++ renderSlapError slapError)
          Right (OutputFileContents output) ->
            assertEqual "SHA1 mismatch" expectedSha (sha1Hex output)
