-- | Top-level test suite. Every test lives in a submodule under
-- 'Props.*', grouped by concern:
--
--   * 'Props.SpecConformance'    — hand-crafted byte-level patches
--                                  testing BPS/UPS spec requirements;
--                                  never goes through slap's create
--                                  functions, so it catches create/parse
--                                  agreement on wrong encodings.
--   * 'Props.RoundTrip'          — per-format create -> parse -> apply
--                                  properties plus format-specific
--                                  round-trip-adjacent assertions (BPS
--                                  block-move efficiency, NINJA1 hashes).
--   * 'Props.Truncation'         — fuzz-style robustness: parse truncated
--                                  patches at random offsets.
--   * 'Props.Identity'           — create(src, src) is an identity patch.
--   * 'Props.Undo'               — UPS/PPF3 apply-then-undo.
--   * 'Props.Contracts'          — conversion contract system and IPS
--                                  sentinel collision detection.
--   * 'Props.Text'               — typed text values with encoding tags;
--                                  the foundation 'Slap.Text' module.
--   * 'Props.Detection'          — DPS detection heuristic.
--   * 'Props.BPSMetadata'        — the BPS metadata glance: the
--                                  UTF-8-or-not classifier, the
--                                  non-printable-escaping display
--                                  primitive, and the non-conformance
--                                  remark.
--   * 'Props.ClassifyTargetCopy' — pure classifier for BPS TargetCopy
--                                  execution strategies.
--   * 'Props.ResolveCopyAddress' — pure resolver of VCDIFF COPY
--                                  addresses into physical reads.
--   * 'Props.ParseWarnings'      — IPS parse-time structural warnings:
--                                  zero-count RLE, overlap, unsorted,
--                                  IPS32 trailing bytes.
--   * 'Props.JSON'               — aeson-backed EBP metadata parser:
--                                  case-insensitive lookup, escaped
--                                  Unicode, nested-object tolerance,
--                                  honest failure on malformed input.
--
-- Shared generators, helpers, and predicates live in 'Props.Helpers'.
module Main (main) where

import qualified Props.BPSMetadata as BPSMetadata
import qualified Props.ClassifyTargetCopy as ClassifyTargetCopy
import qualified Props.Contracts as Contracts
import qualified Props.Detection as Detection
import qualified Props.Identity as Identity
import qualified Props.IPSMarkerPolicy as IPSMarkerPolicy
import qualified Props.JSON as JSON
import qualified Props.Measure as Measure
import qualified Props.Narrow as Narrow
import qualified Props.ParseWarnings as ParseWarnings
import qualified Props.ResolveCopyAddress as ResolveCopyAddress
import qualified Props.RoundTrip as RoundTrip
import qualified Props.SpecConformance as SpecConformance
import qualified Props.Text as Text
import qualified Props.Truncation as Truncation
import qualified Props.Undo as Undo
import qualified Props.XDelta1Conformance as XDelta1Conformance

import Test.Tasty

main :: IO ()
main = defaultMain $ testGroup "Properties"
  [ SpecConformance.specConformanceTests
  , RoundTrip.roundTripTests
  , Truncation.truncationTests
  , Identity.identityTests
  , Undo.undoTests
  , Contracts.contractTests
  , Text.textTests
  , Detection.detectionTests
  , BPSMetadata.bpsMetadataTests
  , ClassifyTargetCopy.classifyTargetCopyTests
  , ResolveCopyAddress.resolveCopyAddressTests
  , ParseWarnings.parseWarningsTests
  , IPSMarkerPolicy.ipsMarkerPolicyTests
  , JSON.jsonTests
  , Measure.measureTests
  , Narrow.narrowTests
  , XDelta1Conformance.xdelta1ConformanceTests
  ]
