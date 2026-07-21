{-# LANGUAGE OverloadedStrings #-}

-- | VCDIFF apply cross-validation. For each row in
-- @test/specs/vcdiff-coreonly.txt@ (stripped-to-core patches) and
-- @test/specs/vcdiff-xdelta3.txt@ (unmodified xdelta3 output:
-- application header and per-window Adler32 intact), slap applies the
-- patch in-process and the result is compared, byte for byte, against
-- xdelta3 applying the same patch — the oracle is xdelta3, never
-- slap. Gated on xdelta3 and on the fixtures (both local-only), so
-- rows skip cleanly where either is absent.
module Integration.VCDIFFApply (vcdiffApplyTests) where

import Integration.External
  ( ExternalTool(..), ExternalRun(..), runExternal )
import Integration.Helpers
  ( Tier, repoDir, parseSpecFile, sha1Hex, withTempFile, mmapRomFile
  , applyPatch, assertFailureT )
import Integration.Skip
  ( GroupPlan, MaybeTest(..), namedGroup, requireExternalTool, requireFixture )
import Slap.SomePatch (parseSome)
import Slap.Status (renderSlapError)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.Convert (noDialectsRequested)
import Slap.FileContents
  ( InputFileContents(..), OutputFileContents(..), PatchFileContents(..) )

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, assertEqual, assertFailure)

vcdiffApplyTests :: Tier -> IO GroupPlan
vcdiffApplyTests _tier = do
  repo <- repoDir
  coreOnlyRows <- parseSpecFile (repo </> "test" </> "specs" </> "vcdiff-coreonly.txt")
  xdelta3Rows  <- parseSpecFile (repo </> "test" </> "specs" </> "vcdiff-xdelta3.txt")
  rowMaybes <- concat <$> mapM (planRow repo) (coreOnlyRows ++ xdelta3Rows)
  fgkMaybes <- fgkBlockSplitTests repo
  pure (namedGroup "vcdiff-apply" (rowMaybes ++ fgkMaybes))

-- | A spec row becomes a runnable test only when both fixtures are
-- present and xdelta3 resolves; otherwise it contributes a typed skip.
planRow :: FilePath -> [String] -> IO [MaybeTest]
planRow repo fields = case fields of
  (baseRelative : patchRelative : label : _) ->
    let basePath  = repo </> baseRelative
        patchPath = repo </> patchRelative
    in requireFixture basePath $ \_ ->
       requireFixture patchPath $ \_ ->
       requireExternalTool Xdelta3 $ \_ ->
         pure [WillRun (mkApplyTest label basePath patchPath)]
  _ -> pure []  -- malformed spec row

-- | A regression fixture for FGK's block bookkeeping. Its section is long
-- enough that the adaptive tree develops a block finer than a full weight
-- run — where the leader a weight bump swaps toward cannot be read from
-- the weights alone (see @rusty-slap/src/xdelta3_fgk.rs@). The patch has
-- no source, so all of it decodes through the FGK coder as one section;
-- expected.bin is the reference decode, committed beside the patch so the
-- check stands on its own without xdelta3 present.
fgkBlockSplitTests :: FilePath -> IO [MaybeTest]
fgkBlockSplitTests repo =
  let patchPath    = repo </> "test" </> "data" </> "fgk-block-split" </> "patch.vcdiff"
      expectedPath = repo </> "test" </> "data" </> "fgk-block-split" </> "expected.bin"
  in requireFixture patchPath $ \_ ->
     requireFixture expectedPath $ \_ ->
       pure [WillRun (mkFgkBlockSplitTest patchPath expectedPath)]

mkFgkBlockSplitTest :: FilePath -> FilePath -> TestTree
mkFgkBlockSplitTest patchPath expectedPath =
  testCase "fgk/a finer-than-weight block decodes to the reference output" $ do
    patchBytes    <- ByteString.readFile patchPath
    expectedBytes <- ByteString.readFile expectedPath
    slapOutput    <- applyWithSlap patchBytes ByteString.empty
    assertEqual "slap output differs from the reference decode"
      (sha1Hex expectedBytes) (sha1Hex slapOutput)

mkApplyTest :: String -> FilePath -> FilePath -> TestTree
mkApplyTest label basePath patchPath =
  testCase label $ do
    baseBytes     <- mmapRomFile basePath
    patchBytes    <- ByteString.readFile patchPath
    slapOutput    <- applyWithSlap patchBytes baseBytes
    xdelta3Output <- applyWithXdelta3 basePath patchPath
    assertEqual "slap output differs from xdelta3"
      (sha1Hex xdelta3Output) (sha1Hex slapOutput)

-- | Parse and apply the patch with slap, in-process.
applyWithSlap :: ByteString -> ByteString -> IO ByteString
applyWithSlap patchBytes baseBytes =
  case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents patchBytes) of
    Left slapError ->
      assertFailureT ("slap parse failed: " <> renderSlapError slapError)
    Right parsed -> do
      result <- applyPatch parsed (InputFileContents baseBytes)
      case result of
        Left slapError ->
          assertFailureT ("slap apply failed: " <> renderSlapError slapError)
        Right (OutputFileContents output) -> pure output

-- | Decode the patch with xdelta3, the oracle, leaving the output in a
-- temp file we read back.
applyWithXdelta3 :: FilePath -> FilePath -> IO ByteString
applyWithXdelta3 basePath patchPath =
  withTempFile "slap-vcdiff-xd3" $ \outputPath -> do
    run <- runExternal Xdelta3 ["-d", "-f", "-s", basePath, patchPath, outputPath] Nothing ""
    case externalRunExitCode run of
      ExitSuccess   -> ByteString.readFile outputPath
      ExitFailure _ -> assertFailure ("xdelta3 failed: " ++ externalRunStderr run)
