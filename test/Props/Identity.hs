-- | Identity property: for every format that supports creation,
--
-- > create(src, src) -> parse -> apply == src
--
-- i.e. creating a patch where source and target are the same bytes
-- produces a valid patch that applies to the source unchanged.
module Props.Identity (identityTests) where

import Slap.Error (CreateResult(..), renderSlapError)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))
import Slap.SomePatch (parseSome)
import Slap.Convert (DirectCreate(..), DiffCreate(..), CreateFormat(..),
                     noMetadataRequested, noConstraintsRequested)
import Slap.Create (createFromMemory)

import qualified Data.ByteString as ByteString
import Test.Tasty
import Test.Tasty.QuickCheck

import Props.Helpers

identityTests :: TestTree
identityTests = testGroup "Identity"
  [ testProperty name (prop_identity format)
  | (name, format) <- allCreateFormats
  ]

allCreateFormats :: [(String, CreateFormat)]
allCreateFormats =
  [ ("BPS",     CreateDiff CreateBPS)
  , ("IPS",     CreateDirect CreateIPS)
  , ("IPS32",   CreateDirect CreateIPS32)
  , ("EBP",     CreateDirect CreateEBP)
  , ("UPS",     CreateDiff CreateUPS)
  , ("PPF3",    CreateDirect CreatePPF3)
  , ("PMSR",    CreateDirect CreatePMSR)
  , ("NINJA1",  CreateDirect CreateNINJA1)
  , ("DPS",     CreateDiff CreateDPS)
  , ("NINJA2",  CreateDiff CreateNINJA2)
  , ("APS-N64", CreateDirect CreateAPSN64)
  , ("APS-GBA", CreateDiff CreateAPSGBA)
  , ("GDIFF",   CreateDiff CreateGDIFF)
  , ("PCHTXT",  CreateDirect CreatePCHTXT)
  ]

-- | For any non-empty source, create(src, src) should be an identity patch.
prop_identity :: CreateFormat -> Property
prop_identity format = forAll genByteString $ \source -> not (ByteString.null source) ==>
  case createFromMemory format (SourceFileContents source) (TargetFileContents source) noMetadataRequested Nothing noConstraintsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> case parseSome patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed -> ioProperty $ do
        result <- applySomePatch parsed (SourceFileContents source)
        pure $ case result of
          Left slapError -> counterexample ("apply: " ++ renderSlapError slapError) $ property False
          Right (TargetFileContents out) -> out === source
