-- | Identity property: for every format that supports creation,
--
-- > create(src, src) -> parse -> apply == src
--
-- i.e. creating a patch where source and target are the same bytes
-- produces a valid patch that applies to the source unchanged.
module Props.Identity (identityTests) where

import Slap.Status (CreateResult(..), renderSlapError)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.SomePatch (parseSome)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.Convert (DirectCreate(..), DifferentialCreate(..), CreateFormat(..),
                     noMetadataRequested, noConstraintsRequested, noDialectsRequested)
import Slap.Create (createPatch)

import Test.Tasty
import Test.Tasty.QuickCheck

import Props.Helpers
import qualified Data.Text as Text

identityTests :: TestTree
identityTests = testGroup "Identity"
  [ testProperty name (prop_identity format)
  | (name, format) <- allCreateFormats
  ]

allCreateFormats :: [(String, CreateFormat)]
allCreateFormats =
  [ ("BPS",     CreateDifferential CreateBPS)
  , ("IPS",     CreateDirect       CreateIPS)
  , ("IPS32",   CreateDirect       CreateIPS32)
  , ("EBP",     CreateDirect       CreateEBP)
  , ("UPS",     CreateDifferential CreateUPS)
  , ("PPF3",    CreateDirect       CreatePPF3)
  , ("PMSR",    CreateDirect       CreatePMSR)
  , ("NINJA1",  CreateDirect       CreateNINJA1)
  , ("DPS",     CreateDifferential CreateDPS)
  , ("NINJA2",  CreateDifferential CreateNINJA2)
  , ("APS-N64", CreateDirect       CreateAPSN64)
  , ("APS-GBA", CreateDifferential CreateAPSGBA)
  , ("GDIFF",   CreateDifferential CreateGDIFF)
  , ("BSDiff",  CreateDifferential CreateBSDiff)
  ]

-- | For any non-empty source, create(src, src) should be an identity patch.
prop_identity :: CreateFormat -> Property
prop_identity format = forAll genNonEmptyByteString $ \source ->
  case createPatch format Nothing (InputFileContents source) (OutputFileContents source) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> case parseSome noDialectsRequested EncodingUtf8 patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right parsed -> ioProperty $ do
        result <- applySomePatch parsed (InputFileContents source)
        pure $ case result of
          Left slapError -> counterexample ("apply: " ++ Text.unpack (renderSlapError slapError)) $ property False
          Right (OutputFileContents out) -> out === source
