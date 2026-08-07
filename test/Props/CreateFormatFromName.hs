{-# LANGUAGE OverloadedStrings #-}

-- | What @slap create@ and @slap convert@ decide to write, from what was asked and what the output is called.
--
-- The contract under test is that slap refuses exactly when it cannot know what is wanted, and never otherwise:
-- a name that speaks is heeded, a name that says nothing leaves the choice alone, and a name that disagrees
-- with the format being written stops the run rather than producing a patch whose extension lies about it.
module Props.CreateFormatFromName (createFormatFromNameTests) where

import Slap.Convert (CreateFormat(..), DirectCreate(..), DifferentialCreate(..), resolveCreateFormat)
import Slap.Status (SlapError(..))

import Test.Tasty
import Test.Tasty.HUnit

createFormatFromNameTests :: TestTree
createFormatFromNameTests = testGroup "create format from the output's name"
  [ testGroup "a name slap understands chooses the format"
      [ readsAs "patch.ips"  (CreateDirect CreateIPS)
      , readsAs "patch.bps"  (CreateDifferential CreateBPS)
      , readsAs "patch.ups"  (CreateDifferential CreateUPS)
      , readsAs "patch.ebp"  (CreateDirect CreateEBP)
        -- the extension four PPF versions share is read as the one people have
      , readsAs "patch.ppf"  (CreateDirect CreatePPF3)
      , readsAs "patch.ppf1" (CreateDirect CreatePPF1)
        -- likewise the extension NINJA1 and NINJA2 share
      , readsAs "patch.rup"  (CreateDifferential CreateNINJA2)
      , readsAs "patch.xdelta3" (CreateDifferential CreateXDelta3)
      , readsAs "PATCH.IPS"  (CreateDirect CreateIPS)
        -- only the last extension speaks
      , readsAs "patch.bps.ips" (CreateDirect CreateIPS)
      ]

  , testGroup "a name that says nothing about format leaves the choice alone"
      [ readsAs "patch.bin" (CreateDifferential CreateBPS)
      , readsAs "patch"     (CreateDifferential CreateBPS)
      , readsAs "patch."    (CreateDifferential CreateBPS)
      , testCase "no output named at all" $
          resolveCreateFormat Nothing Nothing @?= Right (CreateDifferential CreateBPS)
      ]

  , testGroup "a name that could mean several formats is asked about"
      [ asksWhich "patch.aps"
      , asksWhich "patch.vcdiff"
      ]

  , testGroup "a name that disagrees with the format being written stops the run"
      [ contradicts "bps"   (CreateDifferential CreateBPS) "patch.ips"
      , contradicts "ips"   (CreateDirect CreateIPS)       "patch.bps"
      , contradicts "ips32" (CreateDirect CreateIPS32)     "patch.bps"
      ]

  , testGroup "a name the format can honestly wear is left alone"
      [ accepts "ppf1"    (CreateDirect CreatePPF1)          "patch.ppf"
      , accepts "ips32"   (CreateDirect CreateIPS32)         "patch.ips"
      , accepts "aps-n64" (CreateDirect CreateAPSN64)        "patch.aps"
      , accepts "xdelta3" (CreateDifferential CreateXDelta3) "patch.vcdiff"
        -- an unrecognized name is the user's business
      , accepts "bps"     (CreateDifferential CreateBPS)     "patch.whatever"
      ]
  ]
  where
    readsAs outputPath expected = testCase outputPath $
      resolveCreateFormat Nothing (Just outputPath) @?= Right expected

    accepts token wanted outputPath = testCase (outputPath ++ " asked for as " ++ token) $
      resolveCreateFormat (Just wanted) (Just outputPath) @?= Right wanted

    asksWhich outputPath = testCase outputPath $
      case resolveCreateFormat Nothing (Just outputPath) of
        Left (OutputNameNamesSeveralFormats _ _) -> pure ()
        other -> assertFailure ("expected a question about " ++ outputPath ++ ", got " ++ show other)

    contradicts token wanted outputPath = testCase (outputPath ++ " asked for as " ++ token) $
      case resolveCreateFormat (Just wanted) (Just outputPath) of
        Left (OutputNameContradictsFormat {}) -> pure ()
        other -> assertFailure ("expected a refusal for " ++ outputPath ++ ", got " ++ show other)
